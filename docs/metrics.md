# Prometheus Metrics

## Enabling Prometheus 
Specify the port for incoming prometheus connections during 'config init' by using the -d flag.
```
horcrux ..options.. -d 0.0.0.0:6001
```

For earlier adopters, add the following key to your config.yaml

debug-addr: 0.0.0.0:6001

Resulting in a configuration like the following:

```
thresholdMode:
  threshold: 2
  cosigners:
  - shardID: 1
    p2pAddr: tcp://localhost:5001
  - shardID: 2
    p2pAddr: tcp://localhost:5002
  - shardID: 3
    p2pAddr: tcp://localhost:5003
  grpcTimeout: 500ms
  raftTimeout: 500ms
chainNodes:
- privValAddr: tcp://localhost:2300
debugAddr: 0.0.0.0:6001
```

## Prometheus Cautions

Prometheus scrapes data every minute by default which is not fast enough to log metrics which change on a fast interval.

Set the scrape_interval between 1 and 3 seconds in prometheus.yml if you wish to log/monitor these metrics. Note this will take more disk space.

```
global:
  scrape_interval: 3s
```


## Watching Single Signers

Single node signers don't execute any cosigner code, so the basic metrics are:
 * signer_seconds_since_last_precommit 
 * signer_seconds_since_last_prevote
 * signer_last_precommit_height
 * signer_last_prevote_height 

If the 'seconds_since' metrics exceeds the normal block time, it may indicate a sentry failure or a network stall/halt.

If there are skips in the block heights requested to be signed the following counters will increase AFTER the sentry is able to report the latest block height.  Until then, from the perspective of horcrux, it looks no different from a network stall.
 * signer_total_missed_precommits 
 * signer_total_missed_prevotes 

## Watching Sentry Failure

Watch 'signer_sentry_connect_tries' for any increase which indicates retry attempts to reach your sentry.  

If 'signer_total_sentry_connect_tries' is significant, it can indicate network or server issues.

## Watching Cosigner With Grafana

A sample Grafana configuration is available.  See [`horcrux.json`](https://github.com/chillyvee/horcrux-info/blob/master/grafana/horcrux.json)


## Watching For Cosigner Trouble
Metrics may vary between Cosigner processes since there is only one leader.

Watch 'signer_missed_ephemeral_shares' which will note when the leader is not able to get a signature from the peer.  If 'signer_total_missed_ephemeral_shares' increases to a high number, this may indicate a larger issue.

Each block, Nonce Secrets are shared between Cosigners.  Monitoring 'signer_seconds_since_last_local_ephemeral_share_time' and ensuring it does not exceed the block time will allow you to know when a Cosigner was not contacted for a block.

## Metrics that don't always correspond to block time
There is no guarantee that a Cosigner will sign a block if the threshold is reached early.  You may watch 'signer_seconds_since_last_local_sign_start_time' but there is no guarantee that 'signer_seconds_since_last_local_sign_finish_time' will be reached since there are multiple sanity checks that may cause an early exit in some circumstances (rather rare)

## Metrics on the raft leader may be different
On the leader you may watch but these metrics will continue to rise on Cosigners who are not the raft leaders (since followers will rarely manage the original signing request)
 * signer_seconds_since_last_precommit
 * signer_seconds_since_last_prevote

As a result, followers also do not update these metrics
* signer_last_precommit_height
* signer_last_prevote_height 


## Checking Signing Performance
We currently only have metrics between the leader and followers (not full p2p metrics).  However, it is still useful in determining when a particular peer lags significantly.

Your cluster should reach the threshold for availability in a short time.  Monitor the following:

```
signer_sign_block_threshold_lag_seconds{quantile="0.5"} 0.019399953
signer_sign_block_threshold_lag_seconds{quantile="0.9"} 0.028546635
signer_sign_block_threshold_lag_seconds{quantile="0.99"} 0.029730841
```

After reaching the threshold, all cosigners should sign quickly
```
signer_sign_block_cosigner_lag_seconds{quantile="0.5"} 0.031424561
signer_sign_block_cosigner_lag_seconds{quantile="0.9"} 0.0407505
signer_sign_block_cosigner_lag_seconds{quantile="0.99"} 0.045173791
```

If 'signer_sign_block_cosigner_lag_seconds' takes a significant amount of time, you can check the performance of each cosigner as it is seen by the raft leader.  High numbers may indicate a high latency link or a resource.  This metric is only available on the Leader and will report 'NaN' on followers.
```
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5001",quantile="0.5"} 0.010391636
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5001",quantile="0.9"} 0.013242445
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5001",quantile="0.99"} 0.017128885
signer_cosigner_sign_lag_seconds_sum{peerid="tcp://localhost:5001"} 1.1935657130000004
signer_cosigner_sign_lag_seconds_count{peerid="tcp://localhost:5001"} 120
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5002",quantile="0.5"} 0.010473575
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5002",quantile="0.9"} 0.013052952
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5002",quantile="0.99"} 0.01732663
signer_cosigner_sign_lag_seconds_sum{peerid="tcp://localhost:5002"} 1.014658521
signer_cosigner_sign_lag_seconds_count{peerid="tcp://localhost:5002"} 103
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5003",quantile="0.5"} 0.010760536
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5003",quantile="0.9"} 0.012623563
signer_cosigner_sign_lag_seconds{peerid="tcp://localhost:5003",quantile="0.99"} 0.016456836
```


