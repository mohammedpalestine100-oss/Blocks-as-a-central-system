package com.creata.poa.core;

import java.nio.charset.StandardCharsets;

public class Transaction {
  private final String txId;
  private final String from;
  private final String to;
  private final double amount;
  private final long nonce;
  private final String memo;

  public Transaction(String from, String to, double amount, long nonce, String memo) {
    this.from = from; this.to = to; this.amount = amount; this.nonce = nonce; this.memo = memo;
    this.txId = CryptoUtils.sha256(canonical().getBytes(StandardCharsets.UTF_8));
  }
  public String canonical() {
    return "{\"from\":\""+from+"\",\"to\":\""+to+"\",\"amount\":"+amount+","+
           "\"nonce\":"+nonce+",\"memo\":"+(memo==null?"null":"\""+memo+"\"")+"}";
  }
  // getters
  public String getTxId(){ return txId; }
  public String getFrom(){ return from; }
  public String getTo(){ return to; }
  public double getAmount(){ return amount; }
  public long getNonce(){ return nonce; }
  public String getMemo(){ return memo; }
}
