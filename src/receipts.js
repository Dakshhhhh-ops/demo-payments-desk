// Receipt integrity.
// Every receipt carries a checksum so support staff can confirm that a
// receipt a customer forwards has not been edited.
import { createHash } from 'node:crypto';

function canonical(receipt) {
  return JSON.stringify({
    id: receipt.id,
    amount: receipt.amount,
    currency: receipt.currency,
    merchant: receipt.merchant,
    paidAt: receipt.paidAt,
  });
}

export function checksum(receipt) {
  return createHash('sha1').update(canonical(receipt)).digest('hex');
}

export function isUntampered(receipt, expected) {
  return checksum(receipt) === expected;
}
