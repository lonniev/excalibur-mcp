// The Wallet route: the shared wallet, in this site's frame.

import { Wallet } from "@tollbooth-dpyc/web/react";

export default function WalletPage() {
  return (
    <div className="max-w-3xl mx-auto px-4 py-6">
      <Wallet />
    </div>
  );
}
