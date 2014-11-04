/* http_caldav.js -- Admin functions for calendar list
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
var XML_DECLARATION = '<?xml version=\"1.0\" encoding=\"utf-8\"?>';
var XML_NS_DECL = 'xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"';


// Calculate hash of a string
function strHash(str) {
    var i, hash = 0;

    for (i = 0; i < str.length; i++) {
	hash ^= str.charCodeAt(i);
	hash <<= 1;
    }

    return hash;
}


// Create a new calendar collection using data from 'create' form
function createCalendar(url) {
    var create = document.forms.create.elements;

    if (create.name.value.length === 0) {
	window.alert('New calendar MUST have a name');
    }

    // Generate calendar collection name
    var now = new Date();
    var rand = Math.random() * 1000000;
    url += strHash(url).toString(16) +
	'-' + strHash(create.name.value).toString(16) +
	'-' + now.getTime() + '-' + rand.toFixed(0);

    // Build Extended MKCOL body
    var xml = XML_DECLARATION + '<D:mkcol ' + XML_NS_DECL + '>' +
	'<D:set><D:prop>' +
	'<D:resourcetype><D:collection/><C:calendar/></D:resourcetype>' +
	'<D:displayname>' + create.name.value + '</D:displayname>';

    if (create.desc.value.length !== 0) {
	xml += '<C:calendar-description>' + create.desc.value +
	    '</C:calendar-description>';
    }

    if (create.tzid.value.length !== 0) {
	xml += '<C:calendar-timezone-id>' + create.tzid.value +
	    '</C:calendar-timezone-id>';
    }

    var i, compSet = "";
    for (i = 0; i < create.comp.length; i++) {
	if (create.comp[i].checked) {
	    compSet += '<C:comp name=\"' + create.comp[i].value + '\"/>';
	}
    }

    if (compSet !== "") {
	xml += '<C:supported-calendar-component-set>' + compSet +
	    '</C:supported-calendar-component-set>';
    }

    xml += '</D:prop></D:set></D:mkcol>';

    // Send MKCOL request (minimal response)
    var req = new XMLHttpRequest();
    req.open('MKCOL', url, false);
    req.setRequestHeader('Content-Type', 'application/xml');
    req.setRequestHeader('Prefer', 'return=minimal');
    req.send(xml);

    // Refresh calendar list
    document.location.reload();
}


// [Un]share a calendar collection ([un]readable by 'anyone')
function shareCalendar(url, share) {
    // Build ACL body
    var xml = XML_DECLARATION + '<D:acl ' + XML_NS_DECL + '>' +
	'<D:ace><D:principal><D:authenticated/></D:principal>';

    if (share) {
	// Add 'read' privilege
	xml += '<D:grant><D:privilege><D:read/></D:privilege></D:grant>';
    }
    else {
	// Remove 'read' privilege, keeping 'read-free-busy' privilege
	xml += '<D:deny><D:privilege><D:read/></D:privilege></D:deny></D:ace>' +
	    '<D:ace><D:principal><D:authenticated/></D:principal>' +
	    '<D:grant><D:privilege><C:read-free-busy/>' +
	    '</D:privilege></D:grant>';
    }

    xml += '</D:ace></D:acl>';

    // Send ACL request (non-overwrite mode)
    var req = new XMLHttpRequest();
    req.open('ACL', url);
    req.setRequestHeader('Content-Type', 'application/xml');
    req.setRequestHeader('Overwrite', 'F');
    req.send(xml);
}


// Delete a calendar collection
function deleteCalendar(url, name) {
    if (window.confirm('Are you sure you want to delete calendar \"' +
		       name + '\"?')) {
	// Send DELETE request
	var req = new XMLHttpRequest();
	req.open('DELETE', url, false);
	req.send(null);

	// Refresh calendar list
	document.location.reload();
    }
}
