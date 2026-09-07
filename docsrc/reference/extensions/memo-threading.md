# Memo threading

A memo is a message with the `$memo` keyword, stored by a client as a note on
another message in the same account.  Conversation assignment treats a memo
differently from ordinary mail: a memo always belongs to the conversation of
the message it annotates, it never matches on Subject, and it never causes a
conversation to split when the `conversations_max_thread` limit is reached.

## X-ME-Memo-For

A client creating a memo should set this header to the JMAP `blobId` of the
message the memo is for, exactly as JMAP reports it, with its leading `G`:

```
X-ME-Memo-For: G3b9b2e1a0f4d5c6e7a8b9c0d1e2f3a4b5c6d7e8f
```

Cyrus resolves the blobId through the conversations database to the annotated
message's current conversation, including the base conversation id when that
message is in a split conversation.  This is the only reliable way to place a
memo on a message in a split conversation: the message-id index records only
base conversation ids, so `In-Reply-To` alone always resolves to the original
conversation, not the split one.

The header is honoured only on messages carrying `$memo`.  If the blobId is
malformed or names no message in the account, Cyrus logs
`conversations.memo.noparent` at debug level and falls back to `In-Reply-To`.

## Fallbacks

Without `X-ME-Memo-For`, a memo joins the first conversation of the message
named in its `In-Reply-To` header.  Failing that, it threads like ordinary
mail via `References` and `X-ME-Message-ID`, still without the Subject check.
