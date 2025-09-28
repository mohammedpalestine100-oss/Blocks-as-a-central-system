package com.creata.poa.core;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Block {
  private final int index;
  private final long timestamp;
  private final String previousHash;
  private final List<Transaction> transactions;
  private final String merkleRoot;

  private String authorizer;          // "creata"
  private String authoritySignature;  // HMAC على headerWithoutSignature
  private String hash;                // SHA256(headerWithSignature)

  public Block(int index, String previousHash, List<Transaction> txs) {
    this.index = index;
    this.timestamp = Instant.now().getEpochSecond();
    this.previousHash = previousHash;
    this.transactions = Collections.unmodifiableList(new ArrayList<>(txs));
    List<String> txHashes = new ArrayList<>();
    for (Transaction t : txs) txHashes.add(t.getTxId());
    this.merkleRoot = CryptoUtils.merkleRoot(txHashes);
  }

  public String headerWithoutSignature() {
    StringBuilder txs = new StringBuilder();
    for (int i=0;i<transactions.size();i++) {
      if (i>0) txs.append(",");
      txs.append(transactions.get(i).canonical());
    }
    return "{"
      + "\"index\":"+index+","
      + "\"timestamp\":"+timestamp+","
      + "\"previousHash\":\""+previousHash+"\","
      + "\"transactions\":["+txs+"],"
      + "\"merkleRoot\":\""+merkleRoot+"\""
      + "}";
  }
  public String headerWithSignature() {
    return "{"
      + "\"index\":"+index+","
      + "\"timestamp\":"+timestamp+","
      + "\"previousHash\":\""+previousHash+"\","
      + "\"transactions\":[...],"
      + "\"merkleRoot\":\""+merkleRoot+"\","
      + "\"authorizer\":\""+authorizer+"\","
      + "\"authoritySignature\":\""+authoritySignature+"\""
      + "}";
  }

  // setters (used when sealing)
  public void setAuthorizer(String a){ this.authorizer=a; }
  public void setAuthoritySignature(String s){ this.authoritySignature=s; }
  public void setHash(String h){ this.hash=h; }

  // getters
  public int getIndex(){ return index; }
  public long getTimestamp(){ return timestamp; }
  public String getPreviousHash(){ return previousHash; }
  public List<Transaction> getTransactions(){ return transactions; }
  public String getMerkleRoot(){ return merkleRoot; }
  public String getAuthorizer(){ return authorizer; }
  public String getAuthoritySignature(){ return authoritySignature; }
  public String getHash(){ return hash; }
}
