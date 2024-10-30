from bitsets import bitset
from collections import defaultdict
import sys

class PeerTracker:
    def __init__(self, max_peers: int = 3000):
        """
        Initialize PeerTracker with improved memory efficiency.

        Args:
            max_peers: Maximum number of peers to support
        """
        self.max_peers = max_peers
        self.number_of_peers = 0

        # Stores the key as peer string in bytes and the value as ID (int)
        self._peer_to_id = {}
        # Store the actual peer strings in bytes in a list
        self._id_to_peer = []

        # Pre-compute peer_id_list once
        self._bitset_class = bitset("peers", tuple(range(max_peers)))
        self._key_to_peer_bitset = {}

        # Preallocate an empty bitset for unions
        self._empty_bitset = self._bitset_class()

    def add_peer(self, key, peer_string):
        """
        Add a peer to the tracker.

        Args:
            key: The key to associate the peer with
            peer_string: The peer identifier string

        Raises:
            ValueError: If max_peers limit is reached
        """
        key_bytes = key.encode('utf-8')
        peer_bytes = peer_string.encode('utf-8')

        peer_id = self._peer_to_id.get(peer_bytes)
        if peer_id is None:
            if self.number_of_peers >= self.max_peers:
                raise ValueError(f"Maximum peer limit ({self.max_peers}) reached")

            peer_id = self.number_of_peers
            self._peer_to_id[peer_bytes] = peer_id
            self._id_to_peer.append(peer_bytes)
            self.number_of_peers += 1

        # Create or update bitset efficiently
        if key_bytes not in self._key_to_peer_bitset:
            self._key_to_peer_bitset[key_bytes] = self._bitset_class((peer_id,))
        else:
            self._key_to_peer_bitset[key_bytes] = self._key_to_peer_bitset[key_bytes].union(
                self._bitset_class((peer_id,)))

    def get_peers(self, key):
        """
        Get all peers associated with a key.

        Args:
            key: The key to look up peers for

        Returns:
            List of peer strings
        """
        key_bytes = key.encode('utf-8')
        bitset_obj = self._key_to_peer_bitset.get(key_bytes, self._empty_bitset)

        # Decode bytes back to strings
        return [self._id_to_peer[peer_id].decode('utf-8') for peer_id in bitset_obj]

    def get_keys(self):
        """
        Get all keys in the tracker.

        Returns:
            Iterator of key strings
        """
        return (key.decode('utf-8') for key in self._key_to_peer_bitset)

    def clear(self):
        """Clear all data from the tracker."""
        self.number_of_peers = 0
        self._peer_to_id.clear()
        self._id_to_peer.clear()
        self._key_to_peer_bitset.clear()

    def print_memory_stats(self):
        print("***************************")
        print(f"Size of in-memory structs: ")
        print(f"Num. of peers = {self.number_of_peers}")
        print(f"PeerToID map: Len = {len(self._peer_to_id)}, Size = {sys.getsizeof(self._peer_to_id)}")
        print(f"IdToPeer map: Len = {len(self._id_to_peer)}, Size = {sys.getsizeof(self._id_to_peer)}")
        print(f"KeyToPeerBits map: Len = {len(self._key_to_peer_bitset)}, Size = {sys.getsizeof(self._key_to_peer_bitset)}")
        print("***************************")