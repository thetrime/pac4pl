:-module(dhcp,
         [dhcp_wpad/1,
          dhcp_wpad/3,
          dhcp_inform/4]).

:-use_module(pac4pl, [enumerate_network_interfaces/1]).

/** <module> DHCP interface

DHCP requires us to bind to port 68. This may require elevated privileges on some platforms

Currently only the DHCPINFORM message is implemented, and even then only a very few of the
options necessary to get WPAD information. This can be easily extended by adding new clauses
to dhcp_option//1 and optionally to translate_dhcp_option/3

@author    Matt Lilley (matt.lilley@securitease.com)
*/




%   0                   1                   2                   3
%   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
%   +---------------+---------------+---------------+---------------+
%   |                            xid (4)                            |
%   +-------------------------------+-------------------------------+
%   |           secs (2)            |           flags (2)           |
%   +-------------------------------+-------------------------------+
%   |                          ciaddr  (4)                          |
%   +---------------------------------------------------------------+
%   |                          yiaddr  (4)                          |
%   +---------------------------------------------------------------+
%   |                          siaddr  (4)                          |
%   +---------------------------------------------------------------+
%   |                          giaddr  (4)                          |
%   +---------------------------------------------------------------+
%   |                                                               |
%   |                          chaddr  (16)                         |
%   |                                                               |
%   |                                                               |
%   +---------------------------------------------------------------+
%   |                                                               |
%   |                          sname   (64)                         |
%   +---------------------------------------------------------------+
%   |                                                               |
%   |                          file    (128)                        |
%   +---------------------------------------------------------------+
%   |                                                               |
%   |                          options (variable)                   |
%   +---------------------------------------------------------------+

dhcp_wpad(Reply):-
        enumerate_network_interfaces(Interfaces),
        member(interface(Id, ip, IPAddress), Interfaces),
        memberchk(interface(Id, dl, HWAddress), Interfaces),
        dhcp_wpad(HWAddress, IPAddress, Reply),
        !. % Cut member/2 BTP

dhcp_wpad(HWAddress, IPAddress, WPAD):-
        dhcp_inform(HWAddress, IPAddress, [inform, wpad, message_length(2048)], Reply),
        memberchk(wpad=WPAD, Reply).

dhcp_inform(HWAddress, IPAddress, Options, Reply):-
        dhcp_inform_packet(HWAddress, IPAddress, [cookie|Options], Bytes, []),
        atom_codes(Packet, Bytes),
        debug(dhcp, 'Trying ~w (~w)...~n', [HWAddress, IPAddress]),
        setup_call_cleanup(udp_socket(Socket),
                           do_exchange(Socket, Packet, ReplyCodes),
                           tcp_close_socket(Socket)),
        debug(dhcp, 'Got response!~n', []),
        parse_dhcp_packet(Reply, ReplyCodes, []).

do_exchange(Socket, Packet, ReplyCodes):-
        tcp_setopt(Socket, broadcast),
        catch(tcp_bind(Socket, 68),
              Error,
              ( tcp_close_socket(Socket),
                throw(Error)
              )),
        udp_send(Socket, Packet, ip(255,255,255,255):67, []),
        catch(call_with_time_limit(3, udp_receive(Socket, ReplyCodes, _From, [as(codes), max_message_size(2048)])),
              Error,            % Probably a timeout
              ( advise([debug(dhcp)], warning, 'DHCP failed with ~p', [Error]),
                fail
              )).

parse_dhcp_packet(Reply)-->
        {length(DHCPHeader, 236)},
        DHCPHeader,
        dhcp_option(cookie),
        parse_dhcp_packet_1(Reply).

parse_dhcp_packet_1([], [], []):- !. % Actual end of message
parse_dhcp_packet_1([])--> [255], !, parse_dhcp_packet_1(_). % End of message marker. Everything after this is ignored
parse_dhcp_packet_1(Options)--> [0], !, parse_dhcp_packet_1(Options). % Padding after EOM
parse_dhcp_packet_1([Option|Options])-->
        [Code],
        [Length],        
        parse_dhcp_option(Code, Length, Option),
        parse_dhcp_packet_1(Options).

parse_dhcp_option(Code, Length, Option)-->
        {length(Codes, Length)},
        Codes,
        {(translate_dhcp_option(Code, Codes, Option)->
            true
         ; otherwise->
            Option = (Code=Codes)
         )}.


dhcp_message_type(5, ack).

translate_dhcp_option(53, [A], message_type=Key):-
        ( dhcp_message_type(A, Key)->
            true
        ; otherwise->
            Key = unknown(A)
        ).
translate_dhcp_option(252, Codes, wpad=Atom):- atom_codes(Atom, Codes), !.
translate_dhcp_option(54, [A,B,C,D], server_identifier=ip(A,B,C,D)):- !.
translate_dhcp_option(1, [A,B,C,D], subnet_mask=ip(A,B,C,D)):- !.
translate_dhcp_option(3, [A,B,C,D], router=ip(A,B,C,D)):- !.
translate_dhcp_option(6, [A,B,C,D], dns_server=ip(A,B,C,D)):- !.

dhcp_inform_packet(HWAddress, IPAddress, Options)-->
        dhcp_operation(boot_request),
        dhcp_htype(ethernet),
        dhcp_hlen(6),
        dhcp_hops(0),
        dhcp_xid(_),
        dhcp_secs(0),
        dhcp_flags(0),
        dhcp_addr(IPAddress),       % CI
        dhcp_addr(ip(0, 0, 0, 0)),  % YI
        dhcp_addr(ip(0, 0, 0, 0)),  % SI
        dhcp_addr(ip(0, 0, 0, 0)),  % GI
        dhcp_hwaddr(HWAddress),     % CH
        dhcp_sname(''),
        dhcp_file(''),
        dhcp_options(Options).

dhcp_options([]) --> !, dhcp_eom.
dhcp_options([Option|Options]) -->
        dhcp_option(Option),
        dhcp_options(Options).

dhcp_option(cookie) --> [99, 130, 83, 99].
dhcp_option(inform) --> [53, 1, 8].
dhcp_option(wpad) --> [252, 0].
dhcp_option(message_length(L))--> [57, 2], uint16(L).

dhcp_eom --> [255].

dhcp_operation(boot_request)--> [1].
dhcp_operation(boot_reply)--> [2].

dhcp_htype(ethernet)--> [1].

dhcp_hlen(Length)--> [Length].
dhcp_hops(Hops)--> [Hops].

dhcp_xid(Xid)--> {Xid is random(2^32)}, uint32(Xid).

dhcp_secs(S) --> uint16(S).
dhcp_flags(S) --> uint16(S).

dhcp_addr(ip(A,B,C,D))--> [A, B, C, D].
dhcp_hwaddr(mac(A,B,C,D,E,F))--> [A,B,C,D,E,F,0,0,0,0,0,0,0,0,0,0].
dhcp_sname(Atom)-->
        {atom_length(Atom, L),
         ( L > 64 -> throw(type_error(dhcp_sname, Atom)) ; true),
           format(atom(Padded), '~`0t~w~64+', [Atom]),
           atom_codes(Padded, Codes)},
        Codes.

dhcp_file(Atom)-->
        {atom_length(Atom, L),
         ( L > 128 -> throw(type_error(dhcp_filename, Atom)) ; true),
           format(atom(Padded), '~`0t~w~128+', [Atom]),
           atom_codes(Padded, Codes)},
        Codes.

uint32(X)-->
        {A is (X >> 24) /\ 255,
         B is (X >> 16) /\ 255,
         C is (X >> 8) /\ 255,
         D is X /\ 255},
        [A, B, C, D].

uint16(X)-->
        {C is (X >> 8) /\ 255,
         D is X /\ 255},
        [C, D].