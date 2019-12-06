/**
 * This is the IPAddress, each IPAddress object has a lower limit and an upper limit.
 * If an object represents only an ip address, its upper limit and lower limit will be the same.
 */

public class IPAddress {

  private long lower;
  private long upper;

  public IPAddress(long l, long r) {

    lower = l;
    upper = r;
  }

  public long getLower() {
    return lower;
  }

  public long getUpper() {
    return upper;
  }
}
