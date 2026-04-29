"""
Low-level packet probing using Scapy for reliable port state detection.
"""
import asyncio

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


async def rst_probe(ip: str, port: int) -> bool:
    """
    Enhanced RST probe using Scapy for reliable filtered vs closed detection.
    
    Returns:
        True if port is closed (received RST)
        False if port is filtered/no response
    """
    if not SCAPY_AVAILABLE:
        return await rst_probe_fallback(ip, port)
    
    for attempt in range(2):
        timeout = 1.0 + (attempt * 0.5)
        
        try:
            conf.verb = 0
            syn_pkt = IP(dst=ip)/TCP(dport=port, flags="S", seq=1000 + attempt)
            response = sr1(syn_pkt, timeout=timeout, verbose=0)
            
            if response is None:
                continue
            
            if hasattr(response, 'haslayer'):
                if response.haslayer(TCP):
                    tcp_layer = response[TCP]
                    tcp_flags = tcp_layer.flags
                    
                    if tcp_flags & 0x12:
                        return False
                    
                    elif tcp_flags & 0x04:
                        return True
                
                if response.haslayer(ICMP):
                    icmp_layer = response[ICMP]
                    if icmp_layer.type == 3:
                        return False
            
            return False
            
        except Exception as e:
            if attempt == 1:
                pass
            continue
    
    return False


async def rst_probe_fallback(ip: str, port: int) -> bool:
    """
    Fallback method using asyncio when Scapy is unavailable.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=1.0
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except ConnectionRefusedError:
        return True
    except (asyncio.TimeoutError, OSError):
        return False
    except Exception:
        return False