//// Entry point for the synchronicity control plane.
////
//// Subcommands:
////   serve       run the service (role from CP_ROLE: primary | replica)
////   keygen      generate the zone CSK, print DNSKEY / DS / anchor line
////   ds          print DS + anchor material for an existing key
////   seed-admin  create the first user and print a one-time magic link

import gleam/io

pub fn main() {
  io.println("controlplane: scaffold")
}
