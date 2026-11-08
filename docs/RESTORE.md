# Restoring routing data

`edge/routing/current` is the only copy of every mailbox's keys and sequence counter that
the edge reads. Each change is also written, signed, to the routing backup bucket, where S3
keeps every version for 90 days.

Restore only when the live object is lost or corrupt. A restore that uses anything but the
newest backup undoes every mailbox, key rotation, and owner change made since.

## Before you start

You need the operator key, and read access to the backup bucket, which the edge doesn't
have. Only the edge holds `ROUTING_DATA_KEY`, so it does the restore itself, on a request
`edgectl` signs. The backup is already encrypted, so sending it to the edge reveals
nothing.

## Steps

1. **Pick a backup and download it.**

   ```sh
   aws s3api list-object-versions --bucket fount-mail-routing-backup-<account> --prefix routing/current
   aws s3api get-object --bucket fount-mail-routing-backup-<account> --key routing/current \
     --version-id <version> /tmp/routing-backup
   ```

2. **Verify it.** This writes nothing.

   ```sh
   go run ./cmd/edgectl restore -edge <edge host> -operator-key operator.key -backup /tmp/routing-backup
   ```

   Check that the mailbox count and sequence total look right. If `edge/boots` is gone, fetch
   `boots/<boot id>` from the boot log bucket and add `-boot-record <file>`.

3. **Work out the skip.** If this isn't the newest backup, its counters may be below numbers
   already issued. Reusing a number is worse than a gap, so skip past them with
   `-skip-sequences`, using more than the number of messages that could have arrived since
   the backup. Every mailbox then shows a gap the edge can't explain, so tell the broker's
   owner to expect it.

4. **Install it.**

   ```sh
   go run ./cmd/edgectl restore -edge <edge host> -operator-key operator.key \
     -backup /tmp/routing-backup -write -replace -skip-sequences <n>
   ```

   What the edge does depends on its state, which `edgectl status` shows:

   - `no-routing-object`: it writes the backup and finishes booting. Leave off `-replace`.
   - `routing-unreadable`: the object won't decrypt. It needs `-replace`, then finishes
     booting.
   - `serving`: it needs `-replace`. It stops SMTP and the Device API, writes the backup,
     and exits, and its restart policy boots it against the restored object. Senders retry
     during the gap. The answer has `"restarting": true`.

   The write is conditional, so it stops if anything changed the object in the meantime.

5. **Check it.** Wait for `edgectl status` to show `serving`. Check that `RCPT` works for a
   known address, and that the next message gets the expected sequence.

## Drill

Rehearse this before real mail, and after any change to the routing format. Use a scratch
deployment with its own bucket, so the live object is never at risk.
