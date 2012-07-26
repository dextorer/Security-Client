package org.megadevs.security.client.utils;


import java.security.Key;
import java.security.PublicKey;

import javax.xml.crypto.KeySelectorResult;

public class SimpleKeySelectorResult implements KeySelectorResult {
	private PublicKey pk;

	SimpleKeySelectorResult(PublicKey pk) {
		this.pk = pk;
	}

	@Override
	public Key getKey() {
		return this.pk;
	}
}