package com.creata.poa.core;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class CryptoUtils {
  public static String sha256(byte[] data) {
    try {
      MessageDigest d = MessageDigest.getInstance("SHA-256");
      return bytesToHex(d.digest(data));
    } catch (Exception e) { throw new RuntimeException(e); }
  }
  public static String bytesToHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString();
  }
  private static byte[] hexToBytes(String hex) {
    int n = hex.length(); byte[] out = new byte[n/2];
    for (int i=0;i<n;i+=2) out[i/2]=(byte)Integer.parseInt(hex.substring(i,i+2),16);
    return out;
  }
  public static String merkleRoot(List<String> leavesHex) {
    if (leavesHex == null || leavesHex.isEmpty()) return sha256(new byte[0]);
    List<byte[]> layer = new ArrayList<>();
    for (String h : leavesHex) layer.add(hexToBytes(h));
    while (layer.size() > 1) {
      List<byte[]> next = new ArrayList<>();
      for (int i=0;i<layer.size();i+=2) {
        byte[] L = layer.get(i);
        byte[] R = (i+1<layer.size()) ? layer.get(i+1) : L;
        byte[] both = new byte[L.length+R.length];
        System.arraycopy(L,0,both,0,L.length);
        System.arraycopy(R,0,both,L.length,R.length);
        next.add(hexToBytes(sha256(both)));
      }
      layer = next;
    }
    return bytesToHex(layer.get(0));
  }
}
