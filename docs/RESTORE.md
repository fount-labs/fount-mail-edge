# Restoring routing data

`edge/routing/current` is the only copy of every mailbox's keys and sequence counter that
the edge reads. Each change is also written, signed, to the routing backup bucket, where S3
keeps every version for 90 days.

Restore only when the live object is lost or corrupt. A restore that uses anything but the
newest backup undoes every mailbox, key rotation, and owner change made since.

## Before you start

You need the edge's S3 credentials and `ROUTING_DATA_KEY`, and read access to the backup
bucket, which the edge doesn't have. Don't print the secrets or put them in shell history.

## Steps

1. **Stop the edge.**

   ```sh
   tinfoil container stop <edge container>
   ```

   A running edge can't overwrite a restored object, because its next write fails the
   `If-Match` check. It then refuses an older object and fails every routing write until
   it restarts. Stopping it first keeps it from taking mail against the old state.

2. **Pick a backup and download it.**

   ```sh
   aws s3api list-object-versions --bucket fount-mail-routing-backup-<account> --prefix routing/current
   aws s3api get-object --bucket fount-mail-routing-backup-<account> --key routing/current \
     --version-id <version> /tmp/routing-backup
   ```

3. **Verify it.** This writes nothing.

   ```sh
   go run ./cmd/routing-restore -backup /tmp/routing-backup
   ```

   Check that the mailbox count and sequence total look right. If `edge/boots` is gone, fetch
   `boots/<boot id>` from the boot log bucket and add `-boot-record <file>`.

4. **Work out the skip.** If this isn't the newest backup, its counters may be below numbers
   already issued. Reusing a number is worse than a gap, so skip past them with
   `-skip-sequences`, using more than the number of messages that could have arrived since
   the backup. Every mailbox then shows a gap the edge can't explain, so tell the broker's
   owner to expect it.

5. **Install it.**

   ```sh
   go run ./cmd/routing-restore -backup /tmp/routing-backup -write -replace -skip-sequences <n>
   ```

   Leave off `-replace` if the live object is gone. The tool writes conditionally, so it
   stops if anything changed the object in the meantime.

6. **Start the edge.**

   ```sh
   tinfoil container deploy <edge container>
   ```

   Check that it boots, that `RCPT` works for a known address, and that the next message
   gets the expected sequence.

## Drill

Rehearse this before real mail, and after any change to the routing format. Use a scratch
bucket as `S3_BUCKET`, so the live object is never at risk.
