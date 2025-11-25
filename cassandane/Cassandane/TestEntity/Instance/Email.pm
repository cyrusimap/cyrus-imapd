package Cassandane::TestEntity::Instance::Email;
use Moo;

use Cassandane::TestEntity::AutoSetup properties => [ qw(
    blobId threadId mailboxIds keywords size receivedAt
    messageId inReplyTo references sender from to cc bcc replyTo subject sentAt
    bodyStructure bodyValues textBody htmlBody attachments hasAttachment preview
) ];

no Moo;
1;
