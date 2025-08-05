#!/usr/bin/env python3
"""
Cache management module for PhishScanner.

This module provides caching functionality to improve performance
by storing API responses and analysis results.

Author: 0x4hm3d
Version: 2.0
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from cachetools import TTLCache, LRUCache


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    data: Any
    timestamp: float
    ttl: int
    key: str
    source: str


class CacheManager:
    """
    Cache manager for PhishScanner with multiple storage backends.
    
    Supports both in-memory and persistent file-based caching.
    """
    
    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        memory_cache_size: int = 1000,
        default_ttl: int = 3600,
        enable_persistent: bool = True
    ):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory for persistent cache files
            memory_cache_size: Maximum number of items in memory cache
            default_ttl: Default time-to-live in seconds
            enable_persistent: Enable persistent file-based caching
        """
        self.logger = logging.getLogger(__name__)
        self.default_ttl = default_ttl
        self.enable_persistent = enable_persistent
        
        # Initialize memory cache
        self.memory_cache = TTLCache(maxsize=memory_cache_size, ttl=default_ttl)
        
        # Initialize persistent cache directory
        if enable_persistent:
            self.cache_dir = cache_dir or Path.home() / ".phishscanner" / "cache"
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup_expired_files()
        else:
            self.cache_dir = None
    
    def _generate_cache_key(self, key_data: Union[str, Dict[str, Any]]) -> str:
        """
        Generate a cache key from input data.
        
        Args:
            key_data: Data to generate key from
            
        Returns:
            SHA256 hash as cache key
        """
        if isinstance(key_data, str):
            data_str = key_data
        else:
            data_str = json.dumps(key_data, sort_keys=True)
        
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def get(self, key: Union[str, Dict[str, Any]], source: str = "unknown") -> Optional[Any]:
        """
        Get item from cache.
        
        Args:
            key: Cache key or data to generate key from
            source: Source identifier for logging
            
        Returns:
            Cached data if found and valid, None otherwise
        """
        cache_key = self._generate_cache_key(key)
        
        # Try memory cache first
        if cache_key in self.memory_cache:
            self.logger.debug(f"Cache hit (memory): {cache_key[:16]}... from {source}")
            return self.memory_cache[cache_key]
        
        # Try persistent cache
        if self.enable_persistent:
            persistent_data = self._get_from_persistent(cache_key)
            if persistent_data is not None:
                # Add back to memory cache
                self.memory_cache[cache_key] = persistent_data
                self.logger.debug(f"Cache hit (persistent): {cache_key[:16]}... from {source}")
                return persistent_data
        
        self.logger.debug(f"Cache miss: {cache_key[:16]}... from {source}")
        return None
    
    def set(
        self,
        key: Union[str, Dict[str, Any]],
        data: Any,
        ttl: Optional[int] = None,
        source: str = "unknown"
    ) -> None:
        """
        Store item in cache.
        
        Args:
            key: Cache key or data to generate key from
            data: Data to cache
            ttl: Time-to-live in seconds (uses default if None)
            source: Source identifier for logging
        """
        cache_key = self._generate_cache_key(key)
        ttl = ttl or self.default_ttl
        
        # Store in memory cache
        self.memory_cache[cache_key] = data
        
        # Store in persistent cache
        if self.enable_persistent:
            self._set_to_persistent(cache_key, data, ttl, source)
        
        self.logger.debug(f"Cache set: {cache_key[:16]}... from {source} (TTL: {ttl}s)")
    
    def _get_from_persistent(self, cache_key: str) -> Optional[Any]:
        """Get item from persistent cache."""
        try:
            cache_file = self.cache_dir / f"{cache_key}.json"
            
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_entry_data = json.load(f)
            
            # Check if expired
            current_time = time.time()
            if current_time > cache_entry_data['timestamp'] + cache_entry_data['ttl']:
                # Remove expired file
                cache_file.unlink(missing_ok=True)
                return None
            
            return cache_entry_data['data']
            
        except Exception as e:
            self.logger.error(f"Error reading persistent cache: {e}")
            return None
    
    def _set_to_persistent(self, cache_key: str, data: Any, ttl: int, source: str) -> None:
        """Store item in persistent cache."""
        try:
            cache_file = self.cache_dir / f"{cache_key}.json"
            
            cache_entry = CacheEntry(
                data=data,
                timestamp=time.time(),
                ttl=ttl,
                key=cache_key,
                source=source
            )
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(cache_entry), f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Error writing persistent cache: {e}")
    
    def delete(self, key: Union[str, Dict[str, Any]]) -> bool:
        """
        Delete item from cache.
        
        Args:
            key: Cache key or data to generate key from
            
        Returns:
            True if item was deleted, False if not found
        """
        cache_key = self._generate_cache_key(key)
        deleted = False
        
        # Remove from memory cache
        if cache_key in self.memory_cache:
            del self.memory_cache[cache_key]
            deleted = True
        
        # Remove from persistent cache
        if self.enable_persistent:
            cache_file = self.cache_dir / f"{cache_key}.json"
            if cache_file.exists():
                cache_file.unlink()
                deleted = True
        
        if deleted:
            self.logger.debug(f"Cache delete: {cache_key[:16]}...")
        
        return deleted
    
    def clear(self) -> None:
        """Clear all cache entries."""
        # Clear memory cache
        self.memory_cache.clear()
        
        # Clear persistent cache
        if self.enable_persistent and self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                except Exception as e:
                    self.logger.error(f"Error deleting cache file {cache_file}: {e}")
        
        self.logger.info("Cache cleared")
    
    def _cleanup_expired_files(self) -> None:
        """Clean up expired cache files."""
        if not self.enable_persistent or not self.cache_dir.exists():
            return
        
        current_time = time.time()
        cleaned_count = 0
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_entry_data = json.load(f)
                
                # Check if expired
                if current_time > cache_entry_data['timestamp'] + cache_entry_data['ttl']:
                    cache_file.unlink()
                    cleaned_count += 1
                    
            except Exception as e:
                self.logger.error(f"Error checking cache file {cache_file}: {e}")
                # Remove corrupted files
                try:
                    cache_file.unlink()
                    cleaned_count += 1
                except Exception:
                    pass
        
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} expired cache files")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        stats = {
            'memory_cache_size': len(self.memory_cache),
            'memory_cache_maxsize': self.memory_cache.maxsize,
            'memory_cache_ttl': self.memory_cache.ttl,
            'persistent_enabled': self.enable_persistent,
            'default_ttl': self.default_ttl
        }
        
        if self.enable_persistent and self.cache_dir.exists():
            persistent_files = list(self.cache_dir.glob("*.json"))
            stats['persistent_cache_files'] = len(persistent_files)
            
            # Calculate total size
            total_size = sum(f.stat().st_size for f in persistent_files)
            stats['persistent_cache_size_bytes'] = total_size
            stats['persistent_cache_size_mb'] = round(total_size / (1024 * 1024), 2)
        else:
            stats['persistent_cache_files'] = 0
            stats['persistent_cache_size_bytes'] = 0
            stats['persistent_cache_size_mb'] = 0
        
        return stats
    
    def cache_api_response(
        self,
        service: str,
        endpoint: str,
        params: Dict[str, Any],
        response_data: Any,
        ttl: Optional[int] = None
    ) -> None:
        """
        Cache API response with service-specific key.
        
        Args:
            service: Service name (e.g., 'virustotal', 'urlscan')
            endpoint: API endpoint
            params: Request parameters
            response_data: Response data to cache
            ttl: Time-to-live in seconds
        """
        cache_key = {
            'service': service,
            'endpoint': endpoint,
            'params': params
        }
        
        self.set(cache_key, response_data, ttl, f"{service}_api")
    
    def get_api_response(
        self,
        service: str,
        endpoint: str,
        params: Dict[str, Any]
    ) -> Optional[Any]:
        """
        Get cached API response.
        
        Args:
            service: Service name
            endpoint: API endpoint
            params: Request parameters
            
        Returns:
            Cached response data if found, None otherwise
        """
        cache_key = {
            'service': service,
            'endpoint': endpoint,
            'params': params
        }
        
        return self.get(cache_key, f"{service}_api")
    
    def cache_domain_analysis(
        self,
        domain: str,
        analysis_type: str,
        result: Any,
        ttl: Optional[int] = None
    ) -> None:
        """
        Cache domain analysis result.
        
        Args:
            domain: Domain name
            analysis_type: Type of analysis (e.g., 'whois', 'dns')
            result: Analysis result
            ttl: Time-to-live in seconds
        """
        cache_key = f"domain_{analysis_type}_{domain}"
        self.set(cache_key, result, ttl, f"domain_{analysis_type}")
    
    def get_domain_analysis(
        self,
        domain: str,
        analysis_type: str
    ) -> Optional[Any]:
        """
        Get cached domain analysis result.
        
        Args:
            domain: Domain name
            analysis_type: Type of analysis
            
        Returns:
            Cached analysis result if found, None otherwise
        """
        cache_key = f"domain_{analysis_type}_{domain}"
        return self.get(cache_key, f"domain_{analysis_type}")


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


def get_cache_manager(**kwargs) -> CacheManager:
    """
    Get global cache manager instance.
    
    Args:
        **kwargs: Arguments for CacheManager initialization
        
    Returns:
        CacheManager instance
    """
    global _cache_manager
    
    if _cache_manager is None:
        _cache_manager = CacheManager(**kwargs)
    
    return _cache_manager


def clear_global_cache() -> None:
    """Clear global cache."""
    global _cache_manager
    
    if _cache_manager is not None:
        _cache_manager.clear()


def main():
    """CLI interface for cache management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PhishScanner Cache Manager")
    parser.add_argument('--clear', action='store_true', help='Clear all cache')
    parser.add_argument('--stats', action='store_true', help='Show cache statistics')
    parser.add_argument('--cache-dir', type=Path, help='Cache directory path')
    
    args = parser.parse_args()
    
    cache_manager = CacheManager(cache_dir=args.cache_dir)
    
    if args.clear:
        cache_manager.clear()
        print("Cache cleared successfully")
    
    if args.stats:
        stats = cache_manager.get_stats()
        print("Cache Statistics:")
        print(f"  Memory cache: {stats['memory_cache_size']}/{stats['memory_cache_maxsize']} items")
        print(f"  Memory TTL: {stats['memory_cache_ttl']} seconds")
        print(f"  Persistent cache: {'enabled' if stats['persistent_enabled'] else 'disabled'}")
        if stats['persistent_enabled']:
            print(f"  Persistent files: {stats['persistent_cache_files']}")
            print(f"  Persistent size: {stats['persistent_cache_size_mb']} MB")
        print(f"  Default TTL: {stats['default_ttl']} seconds")


if __name__ == "__main__":
    main()