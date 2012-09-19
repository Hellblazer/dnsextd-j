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
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Cache;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.EDNSOption.Code;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SetResponse;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TSIGRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.UpdateLeaseOption;
import org.xbill.DNS.Zone;

import com.hellblazer.dnsextd.util.ByteBufferPool;
import com.hellblazer.pinkie.CommunicationsHandler;
import com.hellblazer.pinkie.CommunicationsHandlerFactory;
import com.hellblazer.pinkie.ServerSocketChannelHandler;
import com.hellblazer.pinkie.SocketChannelHandler;

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
    private class ClientSessionImpl implements CommunicationsHandler,
            ClientSession {

        private ByteBuffer                 buffer;
        private final ClientSessionContext fsm     = new ClientSessionContext(
                                                                              this);
        private SocketChannelHandler       handler;
        private boolean                    inError = false;

        /* (non-Javadoc)
         * @see com.hellblazer.pinkie.CommunicationsHandler#accept(com.hellblazer.pinkie.SocketChannelHandler)
         */
        @Override
        public void accept(SocketChannelHandler handler) {
            this.handler = handler;
            fsm.accept();
        }

        /* (non-Javadoc)
         * @see com.hellblazer.pinkie.CommunicationsHandler#closing()
         */
        @Override
        public void closing() {
            fsm.closing();
        }

        /* (non-Javadoc)
         * @see com.hellblazer.pinkie.CommunicationsHandler#connect(com.hellblazer.pinkie.SocketChannelHandler)
         */
        @Override
        public void connect(SocketChannelHandler handler) {
            throw new UnsupportedOperationException(
                                                    "Outbound connections not supported");
        }

        /* (non-Javadoc)
         * @see com.hellblazer.dnsextd.ClientSession#isInError()
         */
        @Override
        public boolean isInError() {
            return inError;
        }

        @Override
        public void processMessage(Message query, byte[] bytes) {
            OPTRecord queryOPT = query.getOPT();
            if (queryOPT == null || queryOPT.getVersion() != 0) {
                fsm.processed();
                return;
            }
            List<EDNSOption> leases = queryOPT.getOptions(Code.UPDATE_LEASE);
            if (leases.isEmpty()) {
                fsm.passThrough(query);
            }
            if (leases.size() > 1) {
                log.info(String.format("Received %s update lease records",
                                       leases.size()));
                fsm.respond(formatError(query));
                return;
            }

            // We have an update lease query
            UpdateLeaseOption updateLease = (UpdateLeaseOption) leases.get(0);

            TSIGRecord queryTSIG = query.getTSIG();
            TSIG tsig = null;
            if (queryTSIG != null) {
                tsig = tsigs.get(queryTSIG.getName());
                if (tsig == null
                    || tsig.verify(query, bytes, bytes.length, null) != Rcode.NOERROR) {
                    fsm.respond(buildErrorMessage(query.getHeader().clone(),
                                                  Rcode.NOTAUTH, null));
                    return;
                }
            }
            List<Record> updates = query.getSectionList(Section.UPDATE);
        }

        /* (non-Javadoc)
         * @see com.hellblazer.dnsextd.ClientSession#nextMessage()
         */
        @Override
        public void nextMessage() {
            buffer = pool.allocate(4);
            try {
                int read = handler.getChannel().read(buffer);
                if (read < 0) {
                    inError = true;
                    return;
                }
            } catch (IOException e) {
                log.error("Error accepting socket", e);
                return;
            }
            ByteBuffer header = buffer;
            buffer = pool.allocate(header.getInt());
            pool.free(header);
            if (readMessage()) {
                buffer.flip();
                Message message;
                byte[] bytes = new byte[buffer.remaining()];
                buffer.get(bytes);
                try {
                    message = new Message(bytes);
                } catch (IOException e) {
                    log.error(String.format("Error parsing message", e));
                    inError = true;
                    return;
                }
                pool.free(buffer);
                buffer = null;
                fsm.process(message, bytes);
            } else {
                if (inError) {
                    fsm.close();
                } else {
                    handler.selectForRead();
                }
            }
        }

        /* (non-Javadoc)
         * @see com.hellblazer.dnsextd.ClientSession#readMessage()
         */
        @Override
        public boolean readMessage() {
            int read;
            try {
                read = handler.getChannel().read(buffer);
            } catch (IOException e) {
                log.error(String.format("Error reading message from client %s",
                                        handler.getChannel()), e);
                inError = true;
                return false;
            }
            if (read < 0) {
                inError = true;
                return false;
            }

            return buffer.hasRemaining();
        }

        /* (non-Javadoc)
         * @see com.hellblazer.pinkie.CommunicationsHandler#readReady()
         */
        @Override
        public void readReady() {
            fsm.readReady();
        }

        /* (non-Javadoc)
         * @see com.hellblazer.dnsextd.ClientSession#selectForRead()
         */
        @Override
        public void selectForRead() {
            handler.selectForRead();
        }

        /* (non-Javadoc)
         * @see com.hellblazer.dnsextd.ClientSession#selectForWrite()
         */
        @Override
        public void selectForWrite() {
            handler.selectForWrite();
        }

        /* (non-Javadoc)
         * @see com.hellblazer.pinkie.CommunicationsHandler#writeReady()
         */
        @Override
        public void writeReady() {
            fsm.writeReady();
        }
    }

    private final static int                 FLAG_DNSSECOK = 1;
    private final static int                 FLAG_SIGONLY  = 2;
    private final static Logger              log           = LoggerFactory.getLogger(DnsExtd.class);

    private final List<?>                    leases        = null;
    private final Map<Integer, Cache>        caches        = new HashMap<Integer, Cache>();
    private final ServerSocketChannelHandler handler;
    private final ByteBufferPool             pool;
    private final AtomicBoolean              running       = new AtomicBoolean();
    private final Map<Name, TSIG>            tsigs         = new HashMap<Name, TSIG>();
    private final Map<Name, Zone>            znames        = new HashMap<Name, Zone>();

    public DnsExtd(ServerSocketChannelHandler handler, ByteBufferPool pool)
                                                                           throws IOException {
        this.handler = handler;
        this.pool = pool;
        this.handler.setEventHandlerFactory(new CommunicationsHandlerFactory() {
            @Override
            public CommunicationsHandler createCommunicationsHandler(SocketChannel channel) {
                return new ClientSessionImpl();
            }
        });
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

    private byte addAnswer(Message response, Name name, int type, int dclass,
                           int iterations, int flags) {
        SetResponse sr;
        byte rcode = Rcode.NOERROR;

        if (iterations > 6) {
            return Rcode.NOERROR;
        }

        if (type == Type.SIG || type == Type.RRSIG) {
            type = Type.ANY;
            flags |= FLAG_SIGONLY;
        }

        Zone zone = findBestZone(name);
        if (zone != null) {
            sr = zone.findRecords(name, type);
        } else {
            Cache cache = getCache(dclass);
            sr = cache.lookupRecords(name, type, Credibility.NORMAL);
        }

        if (sr.isUnknown()) {
            addCacheNS(response, getCache(dclass), name);
        }
        if (sr.isNXDOMAIN()) {
            response.getHeader().setRcode(Rcode.NXDOMAIN);
            if (zone != null) {
                addSOA(response, zone);
                if (iterations == 0) {
                    response.getHeader().setFlag(Flags.AA);
                }
            }
            rcode = Rcode.NXDOMAIN;
        } else if (sr.isNXRRSET()) {
            if (zone != null) {
                addSOA(response, zone);
                if (iterations == 0) {
                    response.getHeader().setFlag(Flags.AA);
                }
            }
        } else if (sr.isDelegation()) {
            RRset nsRecords = sr.getNS();
            addRRset(nsRecords.getName(), response, nsRecords,
                     Section.AUTHORITY, flags);
        } else if (sr.isCNAME()) {
            CNAMERecord cname = sr.getCNAME();
            RRset rrset = new RRset(cname);
            addRRset(name, response, rrset, Section.ANSWER, flags);
            if (zone != null && iterations == 0) {
                response.getHeader().setFlag(Flags.AA);
            }
            rcode = addAnswer(response, cname.getTarget(), type, dclass,
                              iterations + 1, flags);
        } else if (sr.isDNAME()) {
            DNAMERecord dname = sr.getDNAME();
            RRset rrset = new RRset(dname);
            addRRset(name, response, rrset, Section.ANSWER, flags);
            Name newname;
            try {
                newname = name.fromDNAME(dname);
            } catch (NameTooLongException e) {
                return Rcode.YXDOMAIN;
            }
            rrset = new RRset(new CNAMERecord(name, dclass, 0, newname));
            addRRset(name, response, rrset, Section.ANSWER, flags);
            if (zone != null && iterations == 0) {
                response.getHeader().setFlag(Flags.AA);
            }
            rcode = addAnswer(response, newname, type, dclass, iterations + 1,
                              flags);
        } else if (sr.isSuccessful()) {
            RRset[] rrsets = sr.answers();
            for (RRset rrset : rrsets) {
                addRRset(name, response, rrset, Section.ANSWER, flags);
            }
            if (zone != null) {
                addRRset(zone.getNS().getName(), response, zone.getNS(),
                         Section.AUTHORITY, flags);
                if (iterations == 0) {
                    response.getHeader().setFlag(Flags.AA);
                }
            } else {
                addCacheNS(response, getCache(dclass), name);
            }
        }
        return rcode;
    }

    private void addCacheNS(Message response, Cache cache, Name name) {
        SetResponse sr = cache.lookupRecords(name, Type.NS, Credibility.HINT);
        if (!sr.isDelegation()) {
            return;
        }
        RRset nsRecords = sr.getNS();

        for (Iterator<?> it = nsRecords.rrs(); it.hasNext();) {
            Record r = (Record) it.next();
            response.addRecord(r, Section.AUTHORITY);
        }
    }

    private void addGlue(Message response, Name name, int flags) {
        RRset a = findExactMatch(name, Type.A, DClass.IN, true);
        if (a == null) {
            return;
        }
        addRRset(name, response, a, Section.ADDITIONAL, flags);
    }

    private void addRRset(Name name, Message response, RRset rrset,
                          int section, int flags) {
        for (int s = 1; s <= section; s++) {
            if (response.findRRset(name, rrset.getType(), s)) {
                return;
            }
        }
        if ((flags & FLAG_SIGONLY) == 0) {
            for (Iterator<?> it = rrset.rrs(); it.hasNext();) {
                Record r = (Record) it.next();
                if (r.getName().isWild() && !name.isWild()) {
                    r = r.withName(name);
                }
                response.addRecord(r, section);
            }
        }
        if ((flags & (FLAG_SIGONLY | FLAG_DNSSECOK)) != 0) {
            for (Iterator<?> it = rrset.sigs(); it.hasNext();) {
                Record r = (Record) it.next();
                if (r.getName().isWild() && !name.isWild()) {
                    r = r.withName(name);
                }
                response.addRecord(r, section);
            }
        }
    }

    private void addSOA(Message response, Zone zone) {
        response.addRecord(zone.getSOA(), Section.AUTHORITY);
    }

    private Message buildErrorMessage(Header header, int rcode, Record question) {
        Message response = new Message();
        response.setHeader(header);
        for (int i = 0; i < 4; i++) {
            response.removeAllRecords(i);
        }
        if (rcode == Rcode.SERVFAIL) {
            response.addRecord(question, Section.QUESTION);
        }
        header.setRcode(rcode);
        return response;
    }

    private Zone findBestZone(Name name) {
        Zone foundzone = null;
        foundzone = znames.get(name);
        if (foundzone != null) {
            return foundzone;
        }
        int labels = name.labels();
        for (int i = 1; i < labels; i++) {
            Name tname = new Name(name, i);
            foundzone = znames.get(tname);
            if (foundzone != null) {
                return foundzone;
            }
        }
        return null;
    }

    private RRset findExactMatch(Name name, int type, int dclass, boolean glue) {
        Zone zone = findBestZone(name);
        if (zone != null) {
            return zone.findExactMatch(name, type);
        } else {
            RRset[] rrsets;
            Cache cache = getCache(dclass);
            if (glue) {
                rrsets = cache.findAnyRecords(name, type);
            } else {
                rrsets = cache.findRecords(name, type);
            }
            if (rrsets == null) {
                return null;
            } else {
                return rrsets[0]; /* not quite right */
            }
        }
    }

    private Message formatError(Message in) {
        return buildErrorMessage(in.getHeader().clone(), Rcode.FORMERR, null);
    }

    private Message formatError(byte[] in) {
        Header header;
        try {
            header = new Header(in);
        } catch (IOException e) {
            return null;
        }
        return buildErrorMessage(header, Rcode.FORMERR, null);
    }

    @SuppressWarnings("unused")
    private Message generateReply(Message query, byte[] in, int length, Socket s)
                                                                                 throws IOException {
        Message error = validateHeader(query);
        if (error != null) {
            return error;
        }

        TSIGRecord queryTSIG = query.getTSIG();
        TSIG tsig = null;
        if (queryTSIG != null) {
            tsig = tsigs.get(queryTSIG.getName());
            if (tsig == null
                || tsig.verify(query, in, length, null) != Rcode.NOERROR) {
                return formatError(in);
            }
        }

        int flags = 0;
        OPTRecord queryOPT = query.getOPT();
        if (queryOPT != null && queryOPT.getVersion() > 0) {
        }

        if (queryOPT != null && (queryOPT.getFlags() & ExtendedFlags.DO) != 0) {
            flags = FLAG_DNSSECOK;
        }

        Message response = new Message(query.getHeader().getID());

        response.getHeader().setFlag(Flags.QR);
        if (query.getHeader().getFlag(Flags.RD)) {
            response.getHeader().setFlag(Flags.RD);
        }

        Record queryRecord = query.getQuestion();
        response.addRecord(queryRecord, Section.QUESTION);

        if (!Type.isRR(queryRecord.getType())
            && queryRecord.getType() != Type.ANY) {
            return buildErrorMessage(query.getHeader(), Rcode.NOTIMP,
                                     query.getQuestion());
        }

        byte responseCode = addAnswer(response, queryRecord.getName(),
                                      queryRecord.getType(),
                                      queryRecord.getDClass(), 0, flags);
        if (responseCode != Rcode.NOERROR && responseCode != Rcode.NXDOMAIN) {
            return buildErrorMessage(query.getHeader(), responseCode,
                                     query.getQuestion());
        }
        response.setTSIG(tsig, Rcode.NOERROR, queryTSIG);
        for (Record r : response.getSectionArray(Section.ANSWER)) {
            Name glueName = r.getAdditionalName();
            if (glueName != null) {
                addGlue(response, glueName, flags);
            }
        }
        for (Record r : response.getSectionArray(Section.AUTHORITY)) {
            Name glueName = r.getAdditionalName();
            if (glueName != null) {
                addGlue(response, glueName, flags);
            }
        }

        if (queryOPT != null) {
            int optflags = flags == FLAG_DNSSECOK ? ExtendedFlags.DO : 0;
            OPTRecord opt = new OPTRecord((short) 4096, responseCode, (byte) 0,
                                          optflags);
            response.addRecord(opt, Section.ADDITIONAL);
        }

        return response;
    }

    private Cache getCache(int dclass) {
        Cache c = caches.get(new Integer(dclass));
        if (c == null) {
            c = new Cache(dclass);
            caches.put(new Integer(dclass), c);
        }
        return c;
    }

    /**
     * @param query
     * @return the response message if invalid query header, or null if the
     *         query is valid
     */
    protected Message validateHeader(Message query) {
        Header header = query.getHeader();
        if (!header.getFlag(Flags.QR)) {
            if (header.getRcode() != Rcode.NOERROR) {
                return buildErrorMessage(query.getHeader(), Rcode.FORMERR,
                                         query.getQuestion());
            }
            if (header.getOpcode() != Opcode.QUERY) {
                return buildErrorMessage(query.getHeader(), Rcode.NOTIMP,
                                         query.getQuestion());
            }
        }
        return null;
    }
}
