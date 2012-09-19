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

import java.util.List;
import java.util.concurrent.ScheduledFuture;

import org.xbill.DNS.Record;

/**
 * @author hhildebrand
 * 
 */
public class Lease {
    private final long         duration;
    private final List<Record> updates;
    private ScheduledFuture<?> watchdog;

    /**
     * @param duration
     * @param updates
     */
    public Lease(long duration, List<Record> updates) {
        super();
        this.duration = duration;
        this.updates = updates;
    }

    public long getDuration() {
        return duration;
    }

    public List<Record> getUpdates() {
        return updates;
    }

    public ScheduledFuture<?> getWatchdog() {
        return watchdog;
    }

    public void setWatchdog(ScheduledFuture<?> watchdog) {
        this.watchdog = watchdog;
    }
}
