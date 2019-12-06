import java.io.BufferedReader;

import java.io.File;
import java.io.FileNotFoundException;

import java.io.FileReader;

import java.io.IOException;

import java.util.ArrayList;

import java.util.HashMap;

import java.util.List;

import java.util.Map;

/**
 * This class has two operations. ONe is the constructor. Another one is called accept_packet.
 */
public class Firewall implements wallInterface {


  private String filePath;
  private Map<Integer, List<IPAddress>> inTcp;
  private Map<Integer, List<IPAddress>> outTcp;
  private Map<Integer, List<IPAddress>> inUdp;
  private Map<Integer, List<IPAddress>> outUdp;

  /**
   * this is the constructor.
   *
   * @param path is the path of the file
   */
  public Firewall(String path) {

    filePath = path;
    inTcp = new HashMap<>();
    outTcp = new HashMap<>();
    inUdp = new HashMap<>();
    outUdp = new HashMap<>();
    establishRules();
  }

  /**
   * read data from the file and establish the rules for the firewall.
   */
  private void establishRules() {

    BufferedReader csvReader = null;
    String row = null;
    try {
      csvReader = new BufferedReader(new FileReader(filePath));

      while ((row = csvReader.readLine()) != null) {

        String[] data = row.trim().split(",");
        if (data[0].contains("inbound") && data[1].contains("tcp")) {

          helper(data, inTcp);
        } else if (data[0].contains("inbound") && data[1].contains("udp")) {
          helper(data, inUdp);
        } else if (data[0].contains("outbound") && data[1].contains("tcp")) {
          helper(data, outTcp);
        } else if (data[0].contains("outbound") && data[1].contains("udp")) {
          helper(data, outUdp);
        }
      }
      csvReader.close();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * this function creates entries for port number and ip addresses.
   *
   * @param data contains a rule.
   * @param map  port is the key for each entry and the value is a list of ip addresses
   */
  private static void helper(String[] data, Map<Integer, List<IPAddress>> map) {

    // data[2] means port number or port range
    // check to see if this rule contains a port range or not
    IPAddress ipAddress = null;
    if (data[2].contains("-")) {   // this rule contains a port range.
      String[] ports = data[2].split("-");
      int port1 = Integer.parseInt(ports[0]);
      int port2 = Integer.parseInt(ports[1]);
      int copy = port1;
      while (copy <= port2) {

        map.putIfAbsent(copy, new ArrayList<IPAddress>());
        copy++;
      }

      if (data[3].contains("-")) {    // this rule contains an ip address range
        String[] array = data[3].split("-");
        long result1 = ipConversion(array[0]);
        long result2 = ipConversion(array[1]);
        ipAddress = new IPAddress(result1, result2);
      } else {
        long result = ipConversion(data[3]);
        ipAddress = new IPAddress(result, result);
      }
      copy = port1;
      while (copy <= port2) {

        map.get(copy).add(ipAddress);
        copy++;
      }
    } else {    // this rule only have one port number
      int port = Integer.parseInt(data[2]);
      map.putIfAbsent(port, new ArrayList<IPAddress>());

      if (data[3].contains("-")) {
        String[] array = data[3].split("-");
        long result1 = ipConversion(array[0]);
        long result2 = ipConversion(array[1]);
        ipAddress = new IPAddress(result1, result2);
      } else {
        long result = ipConversion(data[3]);
        ipAddress = new IPAddress(result, result);
      }
      map.get(port).add(ipAddress);
    }
  }

  @Override
  public boolean accept_packet(String direction, String protocol, int port, String address) {

    if (direction.contains("inbound") && protocol.contains("tcp")) {
      if (inTcp.containsKey(port)) {
        return findAddress(inTcp.get(port), address);
      } else {
        return false;
      }
    } else if (direction.contains("inbound") && protocol.contains("udp")) {
      if (inUdp.containsKey(port)) {
        return findAddress(inUdp.get(port), address);
      } else {
        return false;
      }
    } else if (direction.contains("outbound") && protocol.contains("udp")) {
      if (outUdp.containsKey(port)) {
        return findAddress(outUdp.get(port), address);
      } else {
        return false;
      }
    } else if (direction.contains("outbound") && protocol.contains("tcp")) {
      if (outTcp.containsKey(port)) {
        return findAddress(outTcp.get(port), address);
      } else {
        return false;
      }
    }
    return true;
  }

  /**
   * This function simply convert the ip address to a long.
   *
   * @param address is the ip address
   * @return the long result
   */
  private static long ipConversion(String address) {

    String[] array = address.split("\\.");
    long result = 0;

    for (int i = 0; i < array.length; i++) {
      int pow = 3 - i;
      int ip = Integer.parseInt(array[i]);
      result += ip * Math.pow(256, pow);
    }
    return result;
  }

  /**
   * checks to see if the ip address equals one address or within an ip address range.
   *
   * @param addresses is a list of ip addresses
   * @param address   is the target ip address that needs to be found out
   * @return true or false
   */

  private static boolean findAddress(List<IPAddress> addresses, String address) {


    long ipResult = ipConversion(address);
    for (IPAddress each : addresses) {
      if (each.getLower() <= ipResult && each.getUpper() >= ipResult) {
        return true;
      }
    }
    return false;
  }


  public static void main(String[] args) {


    //Firewall firewall = new Firewall(filePath);


//    System.out.println(firewall.accept_packet("inbound", "udp", 53, "192.168.2.1"));
//    System.out.println(firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
//    System.out.println(firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
//    System.out.println(firewall.accept_packet("inbound", "udp", 24, "52.12.48.92"));
  }
}
