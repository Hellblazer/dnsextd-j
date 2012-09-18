/** 
 * (C) Copyright 2012 Hal Hildebrand, all rights reserved.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package com.hellblazer.dnsextd;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hellblazer.pinkie.ServerSocketChannelHandler;

/**
 * A daemon process which provides extension functionality for <a
 * href="files.dns-sd.org/draft-sekar-dns-llq.txt">DNS long lived queries</a>
 * and <a href="files.dns-sd.org/draft-sekar-dns-ul.txt">Dynamic DNS update
 * lease</a> for DNS Service Discovery clients.
 * 
 * @author hhildebrand
 * 
 */
public class DnsExtd {
    @SuppressWarnings("unused")
    private final static Logger              log     = LoggerFactory.getLogger(DnsExtd.class);

    private final ServerSocketChannelHandler handler;
    private final AtomicBoolean              running = new AtomicBoolean();

    public DnsExtd(ServerSocketChannelHandler handler) throws IOException {
        this.handler = handler;
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            handler.start();
        }
    }

    public void terminate() {
        if (running.compareAndSet(true, false)) {
            handler.terminate();
        }
    }
}
