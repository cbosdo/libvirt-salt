'''
An engine that listens for libvirt events and resend them to the sal event bus.

Example configuration:

.. code-block:: yaml

    engines:
        - libvirt_events:
            uri: lxc:///
            tag_prefix: libvirt
            filters:
                - domain/lifecycle
                - domain/reboot

The default URI is ``qemu:///system`` and the default tag prefix is
``salt/engines/libvirt_events``.

If the filters list contains ``all``, all events will be relayed.

:depends: libvirt python binding
'''

import atexit
import logging
import sys
import threading
import traceback
try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse

log = logging.getLogger(__name__)


HAS_LIBVIRT_PY = False
try:
    import libvirt
    if libvirt.getVersion() >= 1000000:
        HAS_LIBVIRT_PY = True
    else:
        log.error('libvirt >= 1.0.0 required')
except:
    pass

# Import salt libs
import salt.utils.event

__virtualname__ = 'libvirt_events'


def __virtual__():
    '''
    Only load if libvirt python binding is present
    '''
    if not HAS_LIBVIRT_PY:
        return (False, 'libvirt_events engine could not be imported')
    return __virtualname__

def nth(stack, index, default=None):
    try:
        return stack[index]
    except IndexError:
        return default

domain_events_map = (
    ( 'defined', ( "added",
                   "updated",
                   "renamed",
                   "from snapshot" ) ),
    ( 'undefined', ( "removed",
                     "renamed" ) ),
    ( 'started', ( "booted",
                   "migrated",
                   "restored",
                   "snapshot",
                   "wakeup" ) ),
    ( 'suspended', ( "paused",
                     "migrated",
                     "ioerror",
                     "watchdog",
                     "restored",
                     "snapshot",
                     "api error",
                     "postcopy",
                     "postcopy failed" ) ),
    ( 'resumed', ( "unpaused",
                   "migrated",
                   "snapshot",
                   "postcopy" ) ),
    ( 'stopped', ( "shutdown",
                   "destroyed",
                   "crashed",
                   "migrated",
                   "saved",
                   "failed",
                   "snapshot" ) ),
    ( 'shutdown', ( "finished",
                    "on guest request",
                    "on host request" ) ),
    ( 'pmsuspended', ( "memory",
                       "disk" ) ),
    ( 'crashed', ( "panicked" ) )
)


def saltSendEvent(opaque, conn, data):
    '''
    Convenience function adding common data to the event and sending it
    on the salt event bus.
    '''
    tag_prefix = opaque['prefix']
    object_type = opaque['object']
    event_type = opaque['event']

    # Prepare the connection URI to fit in the tag
    # qemu+ssh://user@host:1234/system -> qemu+ssh/user@host:1234/system
    uri = urlparse(conn.getURI())
    uri_tag = [uri.scheme]
    if len(uri.netloc) > 0:
        uri_tag.append(uri.netloc)
    path = uri.path.strip('/')
    if len(path) > 0:
        uri_tag.append(path)
    uriStr = "/".join(uri_tag)

    # Append some common data
    all_data = {
        'uri': conn.getURI()
    }
    all_data.update(data)

    tag = '/'.join((tag_prefix, uriStr, object_type, event_type))

    # Actually send the event in salt
    if __opts__.get('__role') == 'master':
        salt.utils.event.get_master_event(
            __opts__,
            __opts__['sock_dir']).fire_event(tag, all_data)
    else:
        __salt__['event.send'](tag, all_data)


def saltSendDomainEvent(opaque, conn, dom, event, event_data):
    data = {
        'domain': {
            'name': dom.name(),
            'id': dom.ID()
         },
         'event': event
    }
    data.update(event_data)
    saltSendEvent(opaque, conn, data)


def domainEventLifecycleCallback (conn, dom, event, detail, opaque):
    eventStr, details = nth(domain_events_map, event, ('unknown', {}))
    detailStr = nth(details, detail, 'unknown')

    saltSendDomainEvent(opaque, conn, dom, eventStr, {
        'detail': detailStr
    })


def domainEventRebootCallback(conn, dom, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], { })


def domainEventRTCChangeCallback(conn, dom, utcoffset, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'utcoffset': utcoffset
    })


def domainEventWatchdogCallback(conn, dom, action, opaque):
    actions = ( 'none', 'pause', 'reset', 'poweroff', 'shutdown', 'debug', 'inject NMI' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'action': nth(actions, action, 'unknown')
    })


def domainEventIOErrorReasonCallback(conn, dom, srcpath, devalias, action, reason, opaque):
    actions = ( 'none', 'pause', 'report' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'srcPath': srcpath,
        'devAlias': devalias,
        'action': nth(actions, action, 'unknown'),
        'reason': reason
    })


def domainEventGraphicsCallback(conn, dom, phase, localAddr, remoteAddr, authScheme, subject, opaque):
    phases = ( 'connect', 'initialize', 'disconnect' )
    families = ( 'ipv4', 'ipv6', 'unix' )

    def getAddress(addr):
        data = { 'family': nth(families, addr.family, 'unknown'),
                 'node': addr.node }
        if addr.service is not None:
            data['service'] = addr.service
        return addr

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'phase': nth(phases, phase, 'unknown'),
        'local': getAddress(localAddr),
        'remote': getAddress(remoteAddr),
        'authScheme': authScheme,
        'subject': {
            'type': subject.type,
            'name': subject.name
        }
    })


def domainEventControlErrorCallback(conn, dom, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {})


def domainEventDiskChangeCallback(conn, dom, oldSrcPath, newSrcPath, devAlias, reason, opaque):
    reasons = ( 'change missing on start', 'drop missing on start' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'oldSrcPath': oldSrcPath,
        'newSrcPath': newSrcPath,
        'devAlias': devAlias,
        'reason': nth(reasons, reason, 'unknown')
    })


def domainEventTrayChangeCallback(conn, dom, devAlias, reason, opaque):
    reasons = ( 'open', 'close' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'devAlias': devAlias,
        'reason': nth(reasons, reason, 'unknown')
    })


def domainEventPMWakeupCallback(conn, dom, reason, opaque):
    reasons = ( )  # Currently unused

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'reason': nth(reasons, reason, 'unknown')
    })


def domainEventPMSuspendCallback(conn, dom, reason, opaque):
    reasons = ( )  # Currently unused

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'reason': nth(reasons, reason, 'unknown')
    })


def domainEventBalloonChangeCallback(conn, dom, actual, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'actual': actual
    })


def domainEventPMSuspendDiskCallback(conn, dom, reason, opaque):
    reasons = ( )  # Currently unused

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'reason': nth(reasons, reason, 'unknown')
    })


def domainEventBlockJobCallback(conn, dom, disk, job_type, status, opaque):
    types = ( 'unknown', 'pull', 'copy', 'commit', 'active commit' )
    statuses = ( 'completed', 'failed', 'canceled', 'ready' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'disk': disk,
        'type': nth(types, job_type, 'unknown'),
        'status': nth(statuses, status, 'unknown')
    })


def domainEventDeviceRemovedCallback(conn, dom, dev, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'dev': dev
    })


def domainEventTunableCallback(conn, dom, params, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'params': params
    })


def domainEventAgentLifecycleCallback(conn, dom, state, reason, opaque):
    states = ( 'connected', 'disconnected' )
    reasons = ( 'unknown', 'domain started', 'channel' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'state': nth(states, state, 'unknown'),
        'reason': nth(reasons, reason, 'unknown')
    })


def domainEventDeviceAddedCallback(conn, dom, dev, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'dev': dev
    })


def domainEventMigrationIteration(conn, dom, iteration, opaque):

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'iteration': iteration
    })


def domainEventJobCompletedCallback(conn, dom, params, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'params': params
    })


def domainEventDeviceRemovalFailedCallback(conn, dom, dev, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'dev': dev
    })


def domainEventMetadataChangeCallback(conn, dom, mtype, nsuri, opaque):
    types = ( 'description', 'title', 'element' )

    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'type': nth(types, mtype, 'unknown'),
        'nsuri': nsuri
    })


def domainEventBlockThresholdCallback(conn, dom, dev, path, threshold, excess, opaque):
    saltSendDomainEvent(opaque, conn, dom, opaque['event'], {
        'dev': dev,
        'path': path,
        'threshold': threshold,
        'excess': excess
    })


def networkEventLifecycleCallback(conn, net, event, detail, opaque):
    events = ( 'defined', 'undefined', 'started', 'stopped' )
    details = ( 'added', 'removed', 'started', 'stopped' )

    saltSendEvent(opaque, conn, {
        'network': net.name(),
        'event': nth(events, event, 'unknown'),
        'detail': nth(details, detail, 'unknown'),
    })


def start(uri="qemu:///system",
          tag_prefix="salt/engines/libvirt_events",
          filters=["all"]):
    try:
        libvirt.virEventRegisterDefaultImpl()

        log.debug('Opening libvirt uri: %s' % uri)
        cnx = libvirt.openReadOnly(uri)

        def cleanup():
            log.debug('Closing libvirt connection: %s' % uri)
            cnx.close()

        atexit.register(cleanup)

        callbacks = {
            'domain': {
                'callbacks': { },
                'register': 'domainEventRegisterAny',
                'deregister': 'domainEventDeregisterAny'
            },
            'network': {
                'callbacks': { },
                'register': 'networkEventRegisterAny',
                'deregister': 'networkEventDeregisterAny'
            }
        }

        def addCallback(obj, event, event_id, callback):
            try:
                libvirt_id = getattr(libvirt, event_id)

                callbacks[obj]['callbacks'][event] = {
                    'type': event_id,
                    'callback': callback
                }
            except AttributeError:
                log.warn('Skip "%s/%s" events: libvirt too old' % (obj, event))

        addCallback('domain', 'lifecycle',
                    'VIR_DOMAIN_EVENT_ID_LIFECYCLE',
                    domainEventLifecycleCallback)
        addCallback('domain', 'reboot',
                    'VIR_DOMAIN_EVENT_ID_REBOOT',
                    domainEventRebootCallback)
        addCallback('domain', 'rtcchange',
                    'VIR_DOMAIN_EVENT_ID_RTC_CHANGE',
                    domainEventRTCChangeCallback)
        addCallback('domain', 'watchdog',
                    'VIR_DOMAIN_EVENT_ID_WATCHDOG',
                    domainEventWatchdogCallback)
        addCallback('domain', 'graphics',
                    'VIR_DOMAIN_EVENT_ID_GRAPHICS',
                    domainEventGraphicsCallback)
        addCallback('domain', 'ioerror',
                    'VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON',
                    domainEventIOErrorReasonCallback)
        addCallback('domain', 'control error',
                    'VIR_DOMAIN_EVENT_ID_CONTROL_ERROR',
                    domainEventControlErrorCallback)
        addCallback('domain', 'disk change',
                    'VIR_DOMAIN_EVENT_ID_DISK_CHANGE',
                    domainEventDiskChangeCallback)
        addCallback('domain', 'tray change',
                    'VIR_DOMAIN_EVENT_ID_TRAY_CHANGE',
                    domainEventTrayChangeCallback)
        addCallback('domain', 'pmwakeup',
                    'VIR_DOMAIN_EVENT_ID_PMWAKEUP',
                    domainEventPMWakeupCallback)
        addCallback('domain', 'pmsuspend',
                    'VIR_DOMAIN_EVENT_ID_PMSUSPEND',
                    domainEventPMSuspendCallback)
        addCallback('domain', 'balloon change',
                    'VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE',
                    domainEventBalloonChangeCallback)
        addCallback('domain', 'pmsuspenddisk',
                    'VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK',
                    domainEventPMSuspendDiskCallback)

        # Handle either BLOCK_JOB or BLOCK_JOB_2, but prefer the latter
        try:
            blockJobId = libvirt.VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2
        except AttributeError:
            blockJobId = libvirt.VIR_DOMAIN_EVENT_ID_BLOCK_JOB
        addCallback('domain', 'block job', blockJobId,
                    domainEventBlockJobCallback)

        addCallback('domain', 'device removed',
                    'VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED',
                    domainEventDeviceRemovedCallback)

        addCallback('domain', 'tunable',
                    'VIR_DOMAIN_EVENT_ID_TUNABLE',
                    domainEventTunableCallback)

        addCallback('domain', 'agent lifecycle',
                    'VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE',
                    domainEventAgentLifecycleCallback)

        addCallback('domain', 'device added',
                    'VIR_DOMAIN_EVENT_ID_DEVICE_ADDED',
                    domainEventDeviceAddedCallback)

        addCallback('domain', 'migration iteration',
                    'VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION',
                    domainEventMigrationIteration)

        addCallback('domain', 'job completed',
                    'VIR_DOMAIN_EVENT_ID_JOB_COMPLETED',
                    domainEventJobCompletedCallback)

        addCallback('domain', 'device removal failed',
                    'VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED',
                    domainEventDeviceRemovalFailedCallback)

        addCallback('domain', 'event metadata change',
                    'VIR_DOMAIN_EVENT_ID_METADATA_CHANGE',
                    domainEventMetadataChangeCallback)

        addCallback('domain', 'block threshold',
                    'VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD',
                    domainEventBlockThresholdCallback)

        addCallback('network', 'lifecycle',
                    'VIR_NETWORK_EVENT_ID_LIFECYCLE',
                    networkEventLifecycleCallback)

        # TODO Add more callbacks


        callbackIds = {}
        allFilters = "all" in filters

        for obj, obj_data in callbacks.items():
            for event_type, callback in obj_data['callbacks'].items():
                event = "/".join((obj, event_type))
                if event in filters or allFilters:
                    register = getattr(cnx, obj_data['register'])
                    id = register(None, callback['type'],
                                  callback['callback'],
                                  { 'prefix': tag_prefix,
                                    'object': obj,
                                    'event': event_type })

                    if obj not in callbackIds:
                        callbackIds[obj] = []

                    callbackIds[obj].append(id)

        def callbacksCleanup():
            for obj, ids in callbackIds.items():
                deregister = getattr(cnx, callbacks[obj]['deregister'])
                for callbackId in ids:
                    deregister(callbackId)

        atexit.register(callbacksCleanup)

        while True:
            libvirt.virEventRunDefaultImpl()

    except Exception:
        raise Exception('%s' % traceback.format_exc())
