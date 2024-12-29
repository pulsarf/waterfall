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
