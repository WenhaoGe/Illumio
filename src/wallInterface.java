/**
 * This is the firewall interface.
 */

public interface wallInterface {

  /**
   * this function checks to see whether the current packet will be blocked by the firewall or not.
   * @param direction the direction of the packet
   * @param protocol the protocol that this packet uses
   * @param port is the port number that this packet uses
   * @param address is the ip address of this packet
   * @return true or false
   */

  boolean accept_packet(String direction, String protocol, int port, String address);
}
