# Waterfall

High level deep packet inspection bypass utility with multiple strategies that can be used together.

## Introduction

Blocking websites by IP address had became a bad practice over time. Such limitations can cause non-related websites to be blocked too. As attempts to block telegram in far tike ago showed that blocking websites by IP can lead to consequences and is ineffective — Deep packet inspection had been brought into the work.
Nowadays, ISPs put devices to complain with the censorship laws in many countries, filter malicious traffic and prevent potential online threats. This tool helps to bypass one of these deep packet inspection usages - Censorship

> Important information will come!
> If you don’t read it, you will likely seek for configurations done by other people.
> Don’t get into that trap! DPI Bypass configurations are different for every ISP.

## Bypass methods

> Most of methods in Waterfall are directed at TCP protocol

### Desynchronization attacks

How would you implement deep packet inspection? For sure, set up a gateway between router and the ISP, and then filter each IP packet.

This is exactly what Russian or Chinese DPI does. However, this method doesn't account for fragmented packets on both IP and applicated protocol level. Waterfall implements much strategies targeted at exploiting this vulnerability.

1. TCP Stream segmentation.

This method has the least drawback on performance, and the least efficiency on practice.

The idea comes from reversing Nagle's alghoritm. If Nagle's Alghoritm merges segments, Split module will split them.

This method will not work if the DPI tries to recover applicated protocol packet.

Deep packet inspection will see the stream like this:
```
|----------|----------|
|  [DATA]  |  [DATA1] |
|----------|----------|
```
2. Data disordering

This method is a modification of tcp segmentation with an extension which's idea is to corrupt first segment on packet level. 
As the result, the first segment will be automatically re-sent. 

This method is way harder to be set up, since you'll have to configure TTL/Hop-by-hop options for packet that will be re-sent.

Deep packet inspection will see the stream like this:
```
|----------|-----------|-----------|----------|
|  [DATA - CORRUPTED]  |  [DATA1]  |  [DATA]  |
|----------|-----------|-----------|----------|
```
3. Sending fake data 

This method is data disordering with an extension that sends a fake data after first segment was sent. If you pass this option multiple times, you will be able to spam data with fakes.

Deep packet inspection will see the stream as follows:
```
|----------|-----------|-----------------|-----------|----------|
|  [DATA - CORRUPTED]  |  [FAKE OF DATA] |  [DATA1]  |  [DATA]  |
|----------|-----------|-----------------|-----------|----------|
```
4. Fake via OOB

This method is same as split, but a fake OOB data will be send in between these segments. This method will work only when the DPI doesn't ignore Out of band bytes.

Deep packet inspection will see the stream as following:
```
|----------|------------------|-----------|
|  [DATA]  | OUT OF BAND DATA |  [DATA1]  |
|----------|------------------|-----------|
```
5. Disordered fake via OOB

This method is same as Fake via OOB, but first segment is corrupted.

DPI will receive streamed bytes as denoted:
```
|----------|-----------|---------------------|-----------|----------|
|  [DATA - CORRUPTED]  |  [OUT OF BAND DATA] |  [DATA1]  |  [DATA]  |
|----------|-----------|---------------------|-----------|----------|
```

## Strategies model

Waterfall offers strategies model, where each strategy the user chooses is being recorded and automatically parsed. The strategy is **always** applied to unchanged segment. 

This means, that if you set a strategy "Split at index with step of 1 from TLS server name indication if found, otherwise zero" and duplicate it with "Disorder at index with step of 1 from TLS server name indication if found, otherwise zero", the first fragment will be left as it was, the second will be split to another 2 fragments, and the first of them will be corrupted.

Here's the schematic representation of what DPI will see:

```
|----------|-----------|-----------|
|  [DATA]  |  [DATA2]  |  [DATA1]  |
|----------|-----------|-----------|
```

Repeating again even simpler: If you pass multiple strategies, the first one will be applied as it is, and the others will be applied to last fragments from previous result.

## Command-line interface

Waterfall offers command line interface for managing the configuration, and keep much less hardcoded values.

Currently, these options are implemented:

```
--split [Offset] - Applies TCP stream segmentation
--disorder [Offset] - Applies TCP stream segmentation, corrupts first part
--fake [Offset] - Applies TCP stream segmentation, corrupts first part and sends a duplicate of it with "yandex.ru" SNI
  if present, otherwise, uses random bytes data with same length.
--oob [Offset] - Applies TCP stream segmentation, sends Out-Of-Band byte with value of '213' between these segments.
--disoob [Offset] - Applies TCP stream segmentation, corrupts first part and sends Out-Of-Band byte with value of '213' between these segments.
```
