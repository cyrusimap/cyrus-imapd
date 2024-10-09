/* http_cal_abook_admin.js -- Admin functions for addressbook and calendar list
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */


// XML constants for requests
var XML_DAV_NS = 'DAV:';
const calendar = new URL(window.location.href).pathname[5] == 'c';
var XML_CALDAV_NS = 'urn:ietf:params:xml:ns:caldav';
const X_CLIENT = 'Cyrus/%s';  // Version filled in by printf() in http_caldav.c/http_carddav.c
const XML_CALCARD_NS = 'urn:ietf:params:xml:ns:ca' + (calendar ? 'ldav' : 'rddav');
const DESCRIPTION = (calendar ? 'calendar' : 'addressbook') + '-description';
const XML_APPLE_NS = 'http://apple.com/ns/ical/';
const XML_CYRUS_NS = 'http://cyrusimap.org/ns/';

function n(i) {
    const h = window.location.href;
    return (h[h.length - 1] == '/' ? h : h + '/') + (i !== undefined ? document.getElementById(i).dataset.url : '');
}

function propupdate(set, i) {
    const doc = document.implementation.createDocument(XML_DAV_NS, "propertyupdate", null);
    const props = doc.createElementNS(XML_DAV_NS, "prop");
    const op = doc.createElementNS(XML_DAV_NS, set ? "set" : "remove");
    doc.documentElement.appendChild(op);
    op.appendChild(props);

    // Send PROPPATCH request (minimal response)
    const req = new XMLHttpRequest();
    req.open('PROPPATCH', n(i));
    req.setRequestHeader('X-Client', X_CLIENT);
    req.setRequestHeader('Prefer', 'return=minimal');
    req.submit = () => req.send(doc);

    return [doc, props, req];
}


// Calculate hash of a string
function strHash(str) {
    var i, hash = 0;

    for (i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash <<= 1;
    }

    return Math.abs(hash);
}


// Create a new collection using data from 'create' form
function createCollection() {
    var create = document.forms.create.elements;

    if (!create.name.value)
        return window.alert('New ' + (calendar ? 'calendar' : 'addressbook') + ' MUST have a name');

    // Generate calendar collection name
    var now = new Date();
    var rand = Math.random() * 1000000;
    const url = n() + strHash(n()).toString(16) +
        '-' + strHash(create.name.value).toString(16) +
        '-' + now.getTime() + '-' + rand.toFixed(0);

    // Build Extended MKCOL document
    var doc = document.implementation.createDocument(XML_DAV_NS,
                                                     "D:mkcol", null);
    var mkcol = doc.documentElement;
    var set = doc.createElementNS(XML_DAV_NS, "D:set");
    mkcol.appendChild(set);

    var props = doc.createElementNS(XML_DAV_NS, "D:prop");
    set.appendChild(props);

    var prop = doc.createElementNS(XML_DAV_NS, "D:resourcetype");
    prop.appendChild(doc.createElementNS(XML_DAV_NS, "D:collection"));
    prop.appendChild(doc.createElementNS(XML_CALCARD_NS, calendar ? "C:calendar" : "C:addressbook"));
    props.appendChild(prop);

    prop = doc.createElementNS(XML_DAV_NS, "D:displayname");
    prop.appendChild(doc.createTextNode(create.name.value));
    props.appendChild(prop);

    if (create.desc.value) {
        prop = doc.createElementNS(XML_CALCARD_NS, DESCRIPTION);
        prop.appendChild(doc.createTextNode(create.desc.value));
        props.appendChild(prop);
    }

    if (create.tzid?.value) {
        prop = doc.createElementNS(XML_CALDAV_NS, "C:calendar-timezone-id");
        prop.appendChild(doc.createTextNode(create.tzid.value));
        props.appendChild(prop);
    }

    var compset = null;
    for (let i = 0; calendar && i < create.comp.length; i++) {
        if (create.comp[i].checked) {
            var comp = doc.createElementNS(XML_CALDAV_NS, "C:comp");
            comp.setAttribute("name", create.comp[i].value);

            if (!compset) {
                compset =
                    doc.createElementNS(XML_CALDAV_NS,
                                        "C:supported-calendar-component-set");
                props.appendChild(compset);
            }
            compset.appendChild(comp);
        }
    }

    // Send MKCOL request (minimal response)
    var req = new XMLHttpRequest();
    req.open('MKCOL', url);
    req.setRequestHeader('X-Client', X_CLIENT);
    req.setRequestHeader('Prefer', 'return=minimal');
    req.addEventListener('load', () => document.location.reload());
    req.send(doc);
}


// [Un]share a calendar/addressbook collection ([un]readable by 'anyone')
function share(i, share) {
    // Build DAV sharing document
    var doc = document.implementation.createDocument(XML_DAV_NS,
                                                     "D:share-resource", null);
    var root = doc.documentElement;

    var sharee = doc.createElementNS(XML_DAV_NS, "D:sharee");
    root.appendChild(sharee);

    var href = doc.createElementNS(XML_DAV_NS, "D:href");
    href.appendChild(doc.createTextNode("DAV:all"));
    sharee.appendChild(href);

    var access = doc.createElementNS(XML_DAV_NS, "D:share-access");
    access.appendChild(doc.createElementNS(XML_DAV_NS,
                                           share ? "D:read" : "D:no-access"));
    sharee.appendChild(access);

    // Send POST request
    var req = new XMLHttpRequest();
    req.open('POST', n(i));
    req.setRequestHeader('X-Client', X_CLIENT);
    req.setRequestHeader('Content-Type', 'application/davsharing+xml');
    req.send(doc);
}

function changeDisplayname(i) {
    const oldName = document.getElementById(i).children[0].innerText;
    const newValue = window.prompt('Provide new name for ' + (calendar ? 'calendar': 'addressbook') + ' ' + oldName, oldName);
    if (newValue == null || newValue == oldName) return;

    const pu = propupdate(newValue != '', i);
    const displayname = pu[0].createElementNS(XML_DAV_NS, "displayname");
    pu[1].appendChild(displayname);
    if (newValue != '')
        displayname.appendChild(pu[0].createTextNode(newValue));
    pu[2].addEventListener('load', () => document.location.reload());
    pu[2].submit();
}

function changeDescription(i) {
    const oldValue = document.getElementById(i).children[2].innerText,
          newValue = window.prompt('Provide new description for ' + (calendar ? 'calendar ': 'addressbook ') + document.getElementById(i).children[0].innerText, oldValue);
    if (newValue == null || newValue == oldValue) return;

    const pu = propupdate(newValue != '', i),
          description = pu[0].createElementNS(XML_CALCARD_NS, DESCRIPTION);
    pu[1].appendChild(description);
    if (newValue != '')
        description.appendChild(pu[0].createTextNode(newValue));
    pu[2].addEventListener('load', () => document.location.reload());
    pu[2].submit();
}

function changeOrder(i, val) {
    const newValue = window.prompt('Provide a posive integer as new order for calendar ' + document.getElementById(i).children[0].innerText, val);
    if (newValue == null || newValue == val) return;
    const num = parseInt(newValue);
    if (newValue != '' && (Number.isNaN(num) || num < 1 || newValue.length != String(num).length)) return window.alert('Not a positive integer');

    const pu = propupdate(newValue != '', i),
          order = pu[0].createElementNS(XML_APPLE_NS, 'calendar-order');
    pu[1].appendChild(order);
    if (newValue != '')
        order.appendChild(pu[0].createTextNode(newValue));
    pu[2].addEventListener('load', () => document.location.reload());
    pu[2].submit();
}

function changeColor(i, set) {
    const pu = propupdate(set, i),
          calcolor = pu[0].createElementNS(XML_APPLE_NS, "calendar-color");
    pu[1].appendChild(calcolor);

    if (set) {
        document.getElementsByName('color' + i)[0].checked = true;
        calcolor.appendChild(pu[0].createTextNode(document.getElementById('cal_' + i).value));
    } else
        document.getElementById('cal_' + i).value = '#808080';
    pu[2].submit();
}

// Make a calendar collection transparent/opaque
function transpCalendar(i, transp) {
    const pu = propupdate(transp, i);
    const caltransp = pu[0].createElementNS(XML_CALDAV_NS,
                                            "C:schedule-calendar-transp");
    pu[1].appendChild(caltransp);

    if (transp)
        caltransp.appendChild(pu[0].createElementNS(XML_CALDAV_NS,
                                                    "C:transparent"));

    pu[2].submit();
}

function scheduling(i, set) {
    const pu = propupdate(!set, i);
    const scheduling_enabled = pu[0].createElementNS(XML_CYRUS_NS, "scheduling-enabled");
    pu[1].appendChild(scheduling_enabled);
    if (!set)
        scheduling_enabled.appendChild(pu[0].createTextNode("F"));

    pu[2].submit();
}


// Adjust supported components on a calendar collection
function compsetCalendar(id, comps) {
    if (!window.confirm('Are you sure you want to change' +
                        ' component types on calendar \"' +
                        document.getElementById(id).children[0].innerText + '\"?')) {

        // Reset selected options
        for (var i = 0; i < comps.length; i++) {
            comps[i].selected = comps[i].defaultSelected;
        }
        return;
    }

    const pu = propupdate(true, id);
    const compset = pu[0].createElementNS(XML_CALDAV_NS,
                                          "C:supported-calendar-component-set");
    compset.setAttribute("force", "yes");
    pu[1].appendChild(compset);

    const op = pu[0].createElementNS(XML_DAV_NS, "D:set");
    for (var i = 0; i < comps.length; i++) {
        if (comps[i].selected) {
            const comp = pu[0].createElementNS(XML_CALDAV_NS, "C:comp");
            comp.setAttribute("name", comps[i].value);
            compset.appendChild(comp);
        }
        comps[i].defaultSelected = comps[i].selected;
    }

    pu[2].submit();
}


function deleteCollection(i) {
    if (window.confirm('Are you sure you want to delete ' + (calendar ? 'calendar \"' : 'addressbook \"') +
                       document.getElementById(i).children[0].innerText + '\"?')) {
        // Send DELETE request
        var req = new XMLHttpRequest();
        req.open('DELETE', n(i));
        req.setRequestHeader('X-Client', X_CLIENT);
        req.addEventListener('load', () => document.location.reload());
        req.send(null);
    }
}

// EOF (%u bytes)
 