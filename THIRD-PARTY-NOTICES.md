# Third-party notices

## Xray-core

Lumen downloads and invokes an unmodified Xray-core executable as a separate
process. Xray-core is maintained at:

https://github.com/XTLS/Xray-core

Review the license and source published by that project before redistribution.
An operator that redistributes a container image containing the executable is
responsible for all applicable license, notice, source-offer and corresponding
source obligations.

## SideRail

The Lumen v32 edge/data-plane architecture was adapted from the connection
model in SideRail by `icubaby`:

https://github.com/icubaby/SideRail

In particular, Lumen retains the model of terminating public TLS at the
Railway edge, forwarding raw WebSocket/HTTPUpgrade streams to loopback Xray,
and proxying XHTTP to loopback Xray. SideRail source files identify themselves
as proprietary and prohibit removal of attribution. Lumen does not claim
authorship or ownership of SideRail.

Lumen's Python/Node implementation, persistence model and existing product
features remain separate. Before redistributing a derived build, obtain and
review the complete SideRail license from its official repository.

## Lumen

توسعه و بروزرسانی Lumen توسط:

https://github.com/EMS115110