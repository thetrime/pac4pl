:-module(pac4pl,
         [flush_pac_cache/0,
          retrieve_pac_file/2,
          enumerate_network_interfaces/1,
          pac/4]).

:-use_foreign_library(foreign(pac4pl)).
:-use_module(library(dhcp)).
:-use_module(library(dcg/basics)).
:-use_module(library(http/http_open)).
            
/** <module> libPAC (Proxy-Auto-Config) interface for Prolog
  
@author    M Lilley (thetrime@gmail.com)
*/


retrieve_pac_file(Source, PacData):-
        ( Source = file(Filename)->
            setup_call_cleanup(open(Filename, read, Stream),
                               read_string(Stream, [], [], _, PacData),
                               close(Stream))
        ; Source = string(PacData)->
            true
        ; Source = detect ->
            debug(proxy, 'Trying to get WPAD info', []),
            with_mutex(wpad_mutex, detect_wpad(PacData)),
            debug(proxy, 'Successfully retrieved WPAD info!', [])      
        ; otherwise->
            throw(type_error(pac_source, Source))
        ).

parse_pac_result([Method|Methods])-->
        blanks,
        pac_method(Method),
        blanks,
        ( ";" ->
            parse_pac_result(Methods)
        ; {Methods = []}
        ).

pac_method(direct)-->
        "DIRECT", !.

pac_method(proxy(Host, Port))-->
        "PROXY ", hostname(Host), ":", integer(Port), !.

pac_method(socks(Host, Port))-->
        "SOCKS ", hostname(Host), ":", integer(Port), !.

hostname(Hostname)-->
        string_without(":", HostnameString),
        {atom_string(Hostname, HostnameString)}.


pac(Source, RequestURL, RequestHostname, ConnectionMethods):-
        ( Source = file(Filename)->
            setup_call_cleanup(open(Filename, read, Stream),
                               read_string(Stream, [], [], _, PacData),
                               close(Stream))
        ; Source = string(PacData)->
            true
        ; Source = detect ->
            debug(proxy, 'Trying to get WPAD info', []),
            with_mutex(wpad_mutex, detect_wpad(PacData)),
            debug(proxy, 'Successfully retrieved WPAD info!', [])      
        ; otherwise->
            throw(type_error(pac_source, Source))
        ),
        ( c_pac(PacData, RequestURL, RequestHostname, PacResult)->
            string_codes(PacResult, PacResultCodes),
            parse_pac_result(ConnectionMethods, PacResultCodes, [])
        ; otherwise->
            ConnectionMethods = []
        ).

:-dynamic(cached_wpad/2).

%%      flush_pac_cache.
%       Empties the PAC cache of any entries. The next lookup will trigger a re-download of the PAC file.

flush_pac_cache:-
        retractall(cached_wpad(_, _)).

detect_wpad(Atom):-
        cached_wpad(Atom, Expiry),
        get_time(CurrentTime),
        CurrentTime < Expiry,
        debug(proxy, 'WPAD was detected within expiry time. Using cached version', []),
        !.

detect_wpad(PacData):-
        debug(proxy, 'No valid cached WPAD information is available. Asking the system...', []),
        system_wpad_url(URL),
        catch(setup_call_cleanup(http_open(URL, Stream, [bypass_proxy(true), timeout(10)]),
                                 read_string(Stream, [], [], _, PacData),
                                 close(Stream)),
              Exception,
              ( debug(proxy, 'DHCP returned ~w for the PAC URL, but when we connected we got ~p', [URL, Exception]),
                fail
              )),          
        !,
        get_time(CurrentTime),
        ExpiryTime is CurrentTime + 30 * 60,
        assert(cached_wpad(PacData, ExpiryTime)).


detect_wpad(PacData):-
        debug(proxy, 'System did not report a valid WPAD URL. Trying to ask the DHCP server (this may not be permitted by the OS)', []),
        retractall(cached_wpad(_, _)),
        catch(dhcp_wpad(URL),  % This requires superuser privileges since we must bind on port 68
              Exception,
              ( debug(proxy, 'Could not use DHCP method because ~p', [Exception]),
                fail)
             ),
        catch(setup_call_cleanup(http_open(URL, Stream, [bypass_proxy(true), timeout(10)]),
                                 read_string(Stream, [], [], _, PacData),
                                 close(Stream)),
              Exception,
              ( debug(proxy, 'DHCP returned ~w for the PAC URL, but when we connected we got ~p', [URL, Exception]),
                fail
              )),             
        !,
        get_time(CurrentTime),
        ExpiryTime is CurrentTime + 30 * 60,
        assert(cached_wpad(PacData, ExpiryTime)).

detect_wpad(Atom):-
        debug(proxy, 'Could not retrieve WPAD via DHCP. Probing for WPAD via DNS... (this may take some time)', []),
        retractall(cached_wpad(_, _)),
        %gethostname(Hostname),
        Hostname = 'securitease.dundas.trime.wtf.im',
        atomic_list_concat(HostnameParts, '.', Hostname),
        detect_wpad_1(HostnameParts, Atom),
        get_time(CurrentTime),
        ExpiryTime is CurrentTime + 30 * 60,
        assert(cached_wpad(Atom, ExpiryTime)).

detect_wpad(Fallback):-
        debug(proxy, 'Unable to automatically detect proxy via WPAD. If you want to use a proxy, either fix the network infrastructure or manually configure a PAC file', []),
        Fallback = 'function FindProxyForURL(url, host) {return "DIRECT";}',
        get_time(CurrentTime),
        % If we do the fallback, try again after just 1 minute
        ExpiryTime is CurrentTime + 1 * 60,
        assert(cached_wpad(Fallback, ExpiryTime)).

detect_wpad_1(HostnameParts, PacData):-
        possible_wpad_url(HostnameParts, URL),
        debug(proxy, 'Trying to get WPAD from ~w', [URL]),
        catch(setup_call_cleanup(http_open(URL, Stream, [bypass_proxy(true), timeout(10)]),
                                 read_string(Stream, [], [], _, PacData),
                                 close(Stream)),
              _,
              fail),
        !.

        
detect_wpad_1(HostnameParts, _):-
        findall(URL,
                possible_wpad_url(HostnameParts, URL),
                URLs),
        atomic_list_concat(URLs, '\n', Message),
        throw(error(format('Unable to find WPAD information at any of the following:\n~w', [Message]), _)).


% Avoid a few common pitfalls. Note that this list is by no means extensive, and it is not practical to test everything thoroughly
possible_wpad_url([_], _):- !, fail. % This would be http://wpad.com or http://wpad.nz or even http://wpad.local
possible_wpad_url([co, _], _):- !, fail. % This would be http://wpad.co.nz or http://wpad.co.uk
possible_wpad_url([com, _], _):- !, fail. % This would be http://wpad.com.au
possible_wpad_url([net, _], _):- !, fail. % This would be http://wpad.net.nz
possible_wpad_url([org, _], _):- !, fail. % This would be http://wpad.org.nz

possible_wpad_url(HostnameParts, URL):-
        ( atomic_list_concat([wpad|HostnameParts], '.', Stem),
          format(atom(URL), 'http://~w/wpad.dat', [Stem])
        ; HostnameParts = [_|Rest],
          possible_wpad_url(Rest, URL)
        ).
        