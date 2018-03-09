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
                    "VIR_DOMAIN_EVENT_ID_LIFECYCLE",
                    domainEventLifecycleCallback)

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
