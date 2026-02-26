"""
Admin API views for the C3DS anomaly detection and investigation features.

All endpoints in this module are protected by IsAdminUser and live under
/api/v1/admin/. Non-admin authenticated users receive HTTP 403.

Features covered:
- US-08: Anomaly flag list + resolve action
- US-09: Anomaly summary by type/severity
- US-10: Event correlation view
- US-12: Incident workspace (CRUD + notes)
- US-13: Detection event time-range filtering (via messages endpoint extension)
- US-14: Heatmap data endpoint
- US-17: Device comparison time-series endpoint
- US-18: Device audit trail
"""
import math
from datetime import timedelta

from django.utils import timezone
from django.db.models import Count
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.permissions import IsAdminUser
from apps.device_management.models import Device, DeviceAuditEntry
from apps.data_processing.models import DeviceMessage

from .models import AnomalyFlag, AnomalyType, Incident, IncidentNote
from .serializers import (
    AnomalyFlagSerializer,
    AnomalySummarySerializer,
    IncidentListSerializer,
    IncidentDetailSerializer,
    IncidentNoteSerializer,
    DeviceAuditEntrySerializer,
)


class AnomalyFlagViewSet(viewsets.ReadOnlyModelViewSet):
    """
    List and retrieve anomaly flags.

    GET  /api/v1/admin/anomaly-flags/           - All flags (filterable)
    GET  /api/v1/admin/anomaly-flags/{id}/      - Flag detail
    POST /api/v1/admin/anomaly-flags/{id}/resolve/ - Resolve a flag
    """
    permission_classes = [IsAdminUser]
    serializer_class = AnomalyFlagSerializer
    pagination_class = None  # Return all flags; table is scrollable on the frontend

    def get_queryset(self):
        qs = AnomalyFlag.objects.select_related('device', 'resolved_by')

        # ?resolved=true|false — default: unresolved only
        resolved_param = self.request.query_params.get('resolved', 'false')
        if resolved_param.lower() == 'true':
            qs = qs.filter(resolved_at__isnull=False)
        elif resolved_param.lower() == 'false':
            qs = qs.filter(resolved_at__isnull=True)
        # 'all' shows everything

        # ?flag_type=SILENT_DEVICE etc.
        flag_type = self.request.query_params.get('flag_type')
        if flag_type:
            qs = qs.filter(flag_type=flag_type)

        # ?severity=HIGH etc.
        severity = self.request.query_params.get('severity')
        if severity:
            qs = qs.filter(severity=severity)

        # ?device=<uuid>
        device_id = self.request.query_params.get('device')
        if device_id:
            qs = qs.filter(device__id=device_id)

        return qs

    @action(detail=True, methods=['post'], url_path='resolve')
    def resolve(self, request, pk=None):
        """
        Mark a flag as resolved.

        POST /api/v1/admin/anomaly-flags/{id}/resolve/

        Records who resolved the flag and when. Resolved flags remain in the
        database for historical reference but are excluded from the default list.
        """
        flag = self.get_object()
        if flag.is_resolved:
            return Response(
                {'error': 'Flag is already resolved.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        flag.resolved_at = timezone.now()
        flag.resolved_by = request.user
        flag.save(update_fields=['resolved_at', 'resolved_by'])

        # Write audit entry for the associated device
        if flag.device:
            from apps.anomaly_detection.audit import log_audit_event
            from apps.device_management.models import AuditEventType
            log_audit_event(
                device=flag.device,
                event_type=AuditEventType.ANOMALY_RESOLVED,
                description=f"Anomaly flag '{flag.get_flag_type_display()}' resolved by {request.user.username}.",
                triggered_by=request.user,
                metadata={'flag_id': flag.id, 'flag_type': flag.flag_type},
            )

        return Response(AnomalyFlagSerializer(flag).data)

class AnomalySummaryView(APIView):
    """
    GET /api/v1/admin/anomaly-flags/summary/

    Returns count of unresolved flags grouped by type and severity.
    Used to populate summary cards on the admin dashboard.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        rows = (
            AnomalyFlag.objects.filter(resolved_at__isnull=True)
            .values('flag_type', 'severity')
            .annotate(count=Count('id'))
            .order_by('severity', 'flag_type')
        )
        serializer = AnomalySummarySerializer(rows, many=True)
        return Response(serializer.data)

def _haversine_km(lat1, lon1, lat2, lon2):
    """
    Calculate great-circle distance in km between two coordinates.

    Reference: Haversine formula, used because SQLite has no geospatial
    extension. Acceptable for small network sizes (< a few hundred devices).
    """
    R = 6371  # Earth radius in km
    phi1, phi2 = math.radians(float(lat1)), math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlambda = math.radians(float(lon2) - float(lon1))
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class EventCorrelationView(APIView):
    """
    GET /api/v1/admin/events/{message_id}/correlate/

    Returns events related to a selected detection event by time and location.

    Query parameters:
    - time_window_minutes: how many minutes before/after to search (default: 30)
    - radius_km: geographic search radius in km (default: 5)

    Devices without lat/lon coordinates are excluded from geographic results but
    appear in temporal results. If the pivot device has no coordinates, only
    temporal correlation is returned.
    """
    permission_classes = [IsAdminUser]

    def get(self, request, message_id):
        try:
            pivot = DeviceMessage.objects.select_related('device').get(id=message_id)
        except DeviceMessage.DoesNotExist:
            return Response({'error': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)

        time_window = int(request.query_params.get('time_window_minutes', 30))
        radius_km = float(request.query_params.get('radius_km', 5))

        # Temporal correlation: events within ±time_window minutes
        time_from = pivot.timestamp - timedelta(minutes=time_window)
        time_to = pivot.timestamp + timedelta(minutes=time_window)

        temporal_qs = (
            DeviceMessage.objects
            .filter(timestamp__gte=time_from, timestamp__lte=time_to)
            .exclude(id=pivot.id)
            .select_related('device')
            .order_by('timestamp')[:50]
        )

        temporal_events = [
            {
                'id': m.id,
                'device_id': str(m.device.id),
                'device_name': m.device.name,
                'message_type': m.message_type,
                'timestamp': m.timestamp.isoformat(),
                'data': m.data,
            }
            for m in temporal_qs
        ]

        geographic_events = []
        pivot_device = pivot.device
        if pivot_device.latitude is not None and pivot_device.longitude is not None:
            nearby_device_ids = []
            for device in Device.objects.exclude(id=pivot_device.id).filter(
                latitude__isnull=False, longitude__isnull=False
            ):
                dist = _haversine_km(
                    pivot_device.latitude, pivot_device.longitude,
                    device.latitude, device.longitude,
                )
                if dist <= radius_km:
                    nearby_device_ids.append(device.id)

            if nearby_device_ids:
                geo_qs = (
                    DeviceMessage.objects
                    .filter(
                        device__id__in=nearby_device_ids,
                        timestamp__gte=time_from,
                        timestamp__lte=time_to,
                    )
                    .select_related('device')
                    .order_by('timestamp')[:50]
                )
                geographic_events = [
                    {
                        'id': m.id,
                        'device_id': str(m.device.id),
                        'device_name': m.device.name,
                        'message_type': m.message_type,
                        'timestamp': m.timestamp.isoformat(),
                        'data': m.data,
                    }
                    for m in geo_qs
                ]

        all_device_ids = {str(pivot_device.id)} | {e['device_id'] for e in geographic_events}
        active_flags = AnomalyFlag.objects.filter(
            device__id__in=all_device_ids,
            resolved_at__isnull=True,
        ).values('id', 'device_id', 'flag_type', 'severity', 'explanation', 'raised_at')

        return Response({
            'pivot_event': {
                'id': pivot.id,
                'device_id': str(pivot_device.id),
                'device_name': pivot_device.name,
                'message_type': pivot.message_type,
                'timestamp': pivot.timestamp.isoformat(),
                'data': pivot.data,
            },
            'temporal_events': temporal_events,
            'geographic_events': geographic_events,
            'active_flags': list(active_flags),
            'search_params': {
                'time_window_minutes': time_window,
                'radius_km': radius_km,
                'has_coordinates': pivot_device.latitude is not None,
            },
        })


class IncidentViewSet(viewsets.ModelViewSet):
    """
    CRUD for investigation incidents.

    GET    /api/v1/admin/incidents/         - List incidents (filterable by status/severity)
    POST   /api/v1/admin/incidents/         - Create incident
    GET    /api/v1/admin/incidents/{id}/    - Incident detail (with flags, messages, notes)
    PATCH  /api/v1/admin/incidents/{id}/    - Update status/severity/title etc.
    DELETE /api/v1/admin/incidents/{id}/    - Delete incident (destructive, use sparingly)
    POST   /api/v1/admin/incidents/{id}/notes/ - Add investigation note
    """
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        qs = Incident.objects.prefetch_related(
            'linked_flags', 'notes', 'linked_messages'
        ).select_related('created_by')

        incident_status = self.request.query_params.get('status')
        if incident_status:
            qs = qs.filter(incident_status=incident_status)

        severity = self.request.query_params.get('severity')
        if severity:
            qs = qs.filter(severity=severity)

        return qs

    def get_serializer_class(self):
        if self.action == 'list':
            return IncidentListSerializer
        return IncidentDetailSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'], url_path='notes')
    def add_note(self, request, pk=None):
        """
        POST /api/v1/admin/incidents/{id}/notes/

        Append an investigation note to an incident. Notes are immutable once
        created — the response is the created note.
        """
        incident = self.get_object()
        serializer = IncidentNoteSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save(incident=incident, author=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class AdminMessageTimelineView(APIView):
    """
    GET /api/v1/admin/messages/timeline/

    Returns detection events for a time window, optimised for the event replay
    view (US-13). Unlike the public messages endpoint this supports arbitrary
    ISO 8601 start/end parameters and returns device coordinates alongside events.

    Query parameters:
    - start: ISO 8601 datetime (required)
    - end:   ISO 8601 datetime (required)
    - device_id: optional UUID filter
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        from dateutil import parser as date_parser

        start_str = request.query_params.get('start')
        end_str = request.query_params.get('end')

        if not start_str or not end_str:
            return Response(
                {'error': 'Both start and end query parameters are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            start = date_parser.isoparse(start_str)
            end = date_parser.isoparse(end_str)
        except Exception:
            return Response(
                {'error': 'Invalid datetime format. Use ISO 8601 (e.g. 2026-02-01T00:00:00Z).'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = (
            DeviceMessage.objects
            .filter(timestamp__gte=start, timestamp__lte=end)
            .select_related('device')
            .order_by('timestamp')
        )

        device_id = request.query_params.get('device_id')
        if device_id:
            qs = qs.filter(device__id=device_id)

        events = [
            {
                'id': m.id,
                'device_id': str(m.device.id),
                'device_name': m.device.name,
                'latitude': float(m.device.latitude) if m.device.latitude else None,
                'longitude': float(m.device.longitude) if m.device.longitude else None,
                'message_type': m.message_type,
                'timestamp': m.timestamp.isoformat(),
                'data': m.data,
            }
            for m in qs[:500]
        ]

        return Response({'events': events, 'count': len(events)})


class DetectionHeatmapView(APIView):
    """
    GET /api/v1/admin/heatmap/

    Returns [lat, lng, weight] tuples for the Leaflet.heat plugin.

    Weight is the number of messages received from that device in the window.
    Devices without coordinates are excluded.

    Query parameters:
    - start: ISO 8601 datetime (default: 24h ago)
    - end:   ISO 8601 datetime (default: now)
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        from dateutil import parser as date_parser

        now = timezone.now()
        start_str = request.query_params.get('start')
        end_str = request.query_params.get('end')

        try:
            start = date_parser.isoparse(start_str) if start_str else now - timedelta(hours=24)
            end = date_parser.isoparse(end_str) if end_str else now
        except Exception:
            return Response({'error': 'Invalid datetime format.'}, status=status.HTTP_400_BAD_REQUEST)

        # Count messages per device in window
        counts = (
            DeviceMessage.objects
            .filter(timestamp__gte=start, timestamp__lte=end)
            .values('device_id')
            .annotate(count=Count('id'))
        )

        # Map device_id → count
        count_map = {str(row['device_id']): row['count'] for row in counts}

        # Build [lat, lng, weight] for devices with coordinates
        points = []
        for device in Device.objects.filter(
            latitude__isnull=False,
            longitude__isnull=False,
            id__in=count_map.keys(),
        ):
            weight = count_map.get(str(device.id), 0)
            if weight > 0:
                points.append({
                    'lat': float(device.latitude),
                    'lng': float(device.longitude),
                    'weight': weight,
                    'device_name': device.name,
                    'device_id': str(device.id),
                })

        return Response({'points': points, 'start': start.isoformat(), 'end': end.isoformat()})

class DeviceComparisonView(APIView):
    """
    GET /api/v1/admin/devices/compare/

    Returns a time-series of the requested metric for each selected device
    over a shared time window, bucketed into hourly intervals.

    Query parameters:
    - device_ids: comma-separated UUIDs (e.g. uuid1,uuid2,uuid3), max 5
    - metric: detection_rate | check_in_interval (default: detection_rate)
    - start: ISO 8601 datetime (default: 7 days ago)
    - end:   ISO 8601 datetime (default: now)
    """
    permission_classes = [IsAdminUser]

    SUPPORTED_METRICS = {'detection_rate', 'check_in_interval'}

    def get(self, request):
        from dateutil import parser as date_parser
        from django.db.models.functions import TruncHour

        device_ids_param = request.query_params.get('device_ids', '')
        device_ids = [d.strip() for d in device_ids_param.split(',') if d.strip()]

        if not device_ids:
            return Response({'error': 'device_ids parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if len(device_ids) > 5:
            return Response({'error': 'Maximum 5 devices can be compared at once.'}, status=status.HTTP_400_BAD_REQUEST)

        metric = request.query_params.get('metric', 'detection_rate')
        if metric not in self.SUPPORTED_METRICS:
            return Response(
                {'error': f"Unsupported metric. Choose from: {', '.join(self.SUPPORTED_METRICS)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = timezone.now()
        try:
            start = date_parser.isoparse(request.query_params['start']) if 'start' in request.query_params else now - timedelta(days=7)
            end = date_parser.isoparse(request.query_params['end']) if 'end' in request.query_params else now
        except Exception:
            return Response({'error': 'Invalid datetime format.'}, status=status.HTTP_400_BAD_REQUEST)

        devices = Device.objects.filter(id__in=device_ids)
        found_ids = {str(d.id) for d in devices}
        missing = set(device_ids) - found_ids
        if missing:
            return Response({'error': f"Devices not found: {', '.join(missing)}"}, status=status.HTTP_404_NOT_FOUND)

        series = {}
        for device in devices:
            if metric == 'detection_rate':
                # Hourly message count
                buckets = (
                    DeviceMessage.objects
                    .filter(device=device, timestamp__gte=start, timestamp__lte=end)
                    .annotate(hour=TruncHour('timestamp'))
                    .values('hour')
                    .annotate(value=Count('id'))
                    .order_by('hour')
                )
                series[str(device.id)] = {
                    'device_name': device.name,
                    'metric': 'detection_rate',
                    'unit': 'messages/hour',
                    'data': [
                        {'time': b['hour'].isoformat(), 'value': b['value']}
                        for b in buckets
                    ],
                }

            elif metric == 'check_in_interval':
                # Interval in seconds between consecutive messages
                messages = list(
                    DeviceMessage.objects
                    .filter(device=device, timestamp__gte=start, timestamp__lte=end)
                    .order_by('timestamp')
                    .values_list('timestamp', flat=True)
                )
                intervals = []
                for i in range(1, len(messages)):
                    delta = (messages[i] - messages[i - 1]).total_seconds()
                    intervals.append({'time': messages[i].isoformat(), 'value': round(delta, 1)})

                series[str(device.id)] = {
                    'device_name': device.name,
                    'metric': 'check_in_interval',
                    'unit': 'seconds',
                    'data': intervals,
                }

        return Response({
            'start': start.isoformat(),
            'end': end.isoformat(),
            'metric': metric,
            'series': series,
        })


class DeviceAuditTrailView(generics.ListAPIView):
    """
    GET /api/v1/admin/devices/{device_id}/audit/

    Returns the full chronological audit trail for a device.

    Query parameters:
    - event_type: filter by event type (e.g. STATUS_CHANGED)
    """
    permission_classes = [IsAdminUser]
    serializer_class = DeviceAuditEntrySerializer

    def get_queryset(self):
        device_id = self.kwargs['device_id']
        qs = DeviceAuditEntry.objects.filter(
            device__id=device_id
        ).select_related('triggered_by')

        event_type = self.request.query_params.get('event_type')
        if event_type:
            qs = qs.filter(event_type=event_type)

        return qs
