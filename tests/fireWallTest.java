import org.junit.Before;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

/**
 * This is the test class to test the public method in FireWall class.
 */
public class fireWallTest {

  private Firewall firewall;

  /**
   * Before testing, I setup a firewall object.
   */

  @Before
  public void setup() {

    String filePath = "/Users/wenhaoge/IdeaProjects/Illumio/rules.csv";

    firewall = new Firewall(filePath);

  }

  /**
   * use four test cases to test accept_packet method.
   */

  @Test
  public void testAcceptPacket() {

    assertEquals(true, firewall.accept_packet("inbound", "udp", 53,
            "192.168.2.1"));
    assertEquals(true, firewall.accept_packet("outbound", "tcp",
            10234, "192.168.10.11"));
    assertEquals(false, firewall.accept_packet("inbound", "tcp",
            81, "192.168.1.2"));
    assertEquals(false, firewall.accept_packet("inbound", "udp",
            24, "52.12.48.92"));
  }

}
