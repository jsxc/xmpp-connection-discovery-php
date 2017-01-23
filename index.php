<?php
header('Content-Type: application/json');

/**
 * Query SRV records according to {@link https://tools.ietf.org/html/rfc6120#section-3.2.1}.
 *
 * @param  String $domain Domain to query
 * @param  array  $methods List of already queried methods
 * @return array
 */
function querySRV($domain, $methods = array()) {
   $srvRecords = dns_get_record('_xmpp-client._tcp.' . $domain, DNS_SRV);

   if($srvRecords) {
      foreach($srvRecords as $srv) {
         if($srv['target'] === '.')
            break;

         $methods['tcp'][] = array(
            'port' => $srv['port'],
            'target' => $srv['target']
         );
      }
   }

   return $methods;
}

/**
 * Query TXT records according to {@link https://xmpp.org/extensions/xep-0156.html#dns}.
 *
 * @param  String $domain Domain to query
 * @param  array  $methods List of already queried methods
 * @return array
 */
function queryTXT($domain, $methods = array()) {
   $records = dns_get_record('_xmppconnect.' . $domain, DNS_TXT);

   if($records) {
      foreach($records as $record) {
         foreach($record['entries'] as $entry) {
            if (preg_match('/^_xmpp-client-(xbosh|websocket)=((wss|https):\/\/.+)/', $entry, $matches)) {
               $methods[$matches[1]][] = $matches[2];
            }
         }
      }
   }

   return $methods;
}

/**
 * Query Web Host Metadata according to {@link https://xmpp.org/extensions/xep-0156.html#http}.
 *
 * @param  String $domain Domain to query
 * @param  array  $methods List of already queried methods
 * @return array
 */
function queryHostMeta($domain, $methods = array()) {
   $hostMeta = @simplexml_load_file('https://' . $domain . '/.well-known/host-meta');

   if (!$hostMeta) {
      $hostMeta = @simplexml_load_file('http://' . $domain . '/.well-known/host-meta');
   }

   if($hostMeta) {
      foreach($hostMeta->children() as $child) {
         if($child->getName() !== 'Link')
            Continue;

         $attributes = $child->attributes();

         if(!preg_match('/^urn:xmpp:alt-connections:(xbosh|websocket)$/', $attributes['rel'], $matches))
            Continue;
         $method = $matches[1];

         if(!preg_match('/^(wss|https):\/\/.+/', $attributes['href'], $matches))
            Continue;
         $href = $matches[0];

         $methods[$method][] = $href;
      }
   }

   return $methods;
}

function main() {
   $methods = array();

   $domain = isset($_GET['domain']) ? $_GET['domain'] : null;
   $domain = preg_match('/^[a-z0-9.-]+$/i', $domain) ? $domain : null;

   if(!$domain)
      return $methods;

   $sources = array('srv', 'txt', 'host-meta');
   $sources = isset($_GET['sources']) ? explode(',', $_GET['sources']) : $sources;

   if (in_array('srv', $sources)) {
      $methods = querySRV($domain, $methods);
   }

   if (in_array('txt', $sources)) {
      $methods = queryTXT($domain, $methods);
   }

   if (in_array('host-meta', $sources)) {
      $methods = queryHostMeta($domain, $methods);
   }

   return $methods;
}

echo json_encode(main());
