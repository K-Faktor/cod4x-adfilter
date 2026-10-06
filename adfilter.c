/*===================================================================*\
||///////////////////////////////////////////////////////////////////||
||/////  _  \ |    |/ _|   |    |//////  _  \/////|   |/\_ ____ \////||
||////  /_\  \|      < |   |    |/////  /_\  \////|   |//| |  |  \///||
||///    |    \    |  \|   |    |////    |    \///|   |//| |__|   \//||
||//\____|__  /____|__ \___|_______ \____|__  ////|___|//_______  ///||
||//////////\/////////\////////////\////////\///////////////////\////||
||===================================================================||
||            LICENSED UNDER THE MIT LICENSE - OPEN SOURCE           ||
\*===================================================================*/

#include <stdlib.h>
#include <string.h>
#include "adfilter.h"
#include "../pinc.h"
#include <stdbool.h>
#include <ctype.h>

void Q_strncpyz(char *dest, const char *src, int destsize) {
    if (!dest) {
        Plugin_Error(P_ERROR_DISABLE, "Q_strncpyz: NULL dest");
    }
    if (!src) {
        Plugin_Error(P_ERROR_DISABLE, "Q_strncpyz: NULL src");
    }
    if (destsize < 1) {
        Plugin_Error(P_ERROR_DISABLE, "Q_strncpyz: destsize < 1");
    }

    strncpy(dest, src, destsize - 1);
    dest[destsize - 1] = 0;
}

const char* COMMON_TLDS[] = {
    // Classic gTLDs (generic top-level domains)
    "com", "net", "org", "edu", "gov", "mil", "int",
    
    // Popular ccTLDs (country code top-level domains)
    "io", "me", "tv", "gg", "co", "uk", "de", "fr", "ru", "cn", "jp", "us", "ca", "au", "in",
    "br", "it", "es", "nl", "ch", "se", "no", "fi", "dk", "pl", "be", "at", "cz", "gr", "pt", 
    "ie", "nz", "za", "mx", "ar", "kr", "sg", "hk", "tw", "th", "vn", "id", "my", "ph",
    
    // New gTLDs (generic top-level domains)
    "xyz", "info", "biz", "online", "site", "website", "app", "dev", "club", "shop", "store", "live",
    "tech", "space", "top", "pro", "name", "mobi", "asia", "cat", "jobs", "tel", "travel", "xxx",
    "cloud", "digital", "media", "news", "blog", "email", "design", "art", "music", "video", "games",
    "agency", "company", "group", "solutions", "services", "systems", "network", "software", "codes",
    "ai", "ml", "bot", "crypto", "blockchain", "nft", "wallet", "finance", "bank", "capital",
    "health", "care", "clinic", "doctor", "fitness", "yoga", "food", "coffee", "restaurant", "pizza",
    "hotel", "tour", "vacation", "holiday", "flight", "cruise", "taxi", "car", "auto",
    "fashion", "style", "beauty", "shoes", "jewelry", "watches", "toys", "kids", "family", "love",
    "home", "house", "property", "estate", "rentals", "construction", "build", "repair", "tools",
    "academy", "school", "university", "education", "courses", "training", "coach", "expert",
    "law", "legal", "attorney", "tax", "accountant", "consulting", "management", "marketing",
    "photo", "photography", "pictures", "gallery", "studio", "production", "works", "ventures",
    "ltd", "llc", "inc", "gmbh", "team", "partners", "associates", "international",
    "world", "global", "earth", "planet", "eco", "green", "energy", "solar", "wind", "power",
    
    // Sponsored / specialized TLDs
    "museum", "aero", "coop", "post",
    
    // IDN TLDs (internationalized domain names)
    "рф", "укр", "бг", "срб", "қаз", "мон", "ελ", "ευ", "中国", "香港", "台湾", "日本", "한국", 
    "भारत", "ਭਾਰਤ", "ભારત", "இந்தியா", "مصر", "السعودية", "امارات", "پاکستان", "ایران", "ישראל", "ไทย", 
    "ລາວ", "မြန်မာ", "ភ្នំពេញ", "संगठन", "ভারত", "ভাৰত",
    
    NULL  // Terminator
};

bool isAlphanumericOrHyphen(char c) {
    return isalnum(c) || c == '-';
}

// Helper function to check if string contains implaza.lk (case insensitive)
bool containsWhitelistedDomain(const char *msg) {
    char *lower = strdup(msg);
    if (!lower) return false;
    
    // Convert to lowercase for case-insensitive comparison
    for (int i = 0; lower[i]; i++) {
        lower[i] = tolower(lower[i]);
    }
    
    bool contains = strstr(lower, "implaza.lk") != NULL;
    free(lower);
    return contains;
}

bool hasIP(const char *msg) {
    int dots = 0;
    int numbers = 0;
    bool foundPotentialIP = false;
    int len = strlen(msg);
    
    // First pass: Look for basic pattern of numbers and dots
    for(int i = 0; i < len; i++) {
        char c = msg[i];
        
        // Check for number or number-like characters
        if(isdigit(c) || c == 'o' || c == 'O' || c == 'i' || c == 'I' || c == 'l' || c == 'L') {
            numbers++;
            if(dots == 3 && numbers <= 3) {
                foundPotentialIP = true;
                break;
            }
        }
        // Check for dot or dot-like characters
        else if(c == '.' || c == ',' || c == ' ' || c == '-' || c == '/' || c == '\\') {
            if(numbers > 0 && numbers <= 3) {
                dots++;
                numbers = 0;
            }
        }
        else {
            // Reset if we encounter any other character
            if(!(dots == 3 && numbers <= 3)) {
                dots = 0;
                numbers = 0;
            }
        }
    }

    // Second pass: Look for repeated patterns that might be IPs
    if(!foundPotentialIP) {
        char prevChar = 0;
        int repeats = 0;
        int separators = 0;
        
        for(int i = 0; i < len; i++) {
            char c = msg[i];
            
            if(c == '.' || c == ',' || c == ' ' || c == '-' || c == '/' || c == '\\') {
                separators++;
                if(separators == 3 && repeats >= 3) {
                    foundPotentialIP = true;
                    break;
                }
            }
            else if(c == prevChar || 
                   (prevChar == 'i' && c == 'I') || 
                   (prevChar == 'I' && c == 'i') ||
                   (prevChar == 'l' && c == 'L') ||
                   (prevChar == 'L' && c == 'l') ||
                   (prevChar == 'o' && c == 'O') ||
                   (prevChar == 'O' && c == 'o')) {
                repeats++;
            }
            prevChar = c;
        }
    }

    return foundPotentialIP;
}

bool hasDomain(const char *msg) {
    int len = strlen(msg);
    if (len < 4) return false;  // Minimum length for a valid domain (a.io)
    
    // Temporary buffer for domain parts
    char part[256];
    int partLen = 0;
    int dots = 0;
    bool hasDot = false;
    bool hasValidChar = false;
    
    for (int i = 0; i < len; i++) {
        char c = tolower(msg[i]);
        
        // Handle domain-like patterns with common substitutions
        if (c == '(' || c == '[' || c == '{') c = '.';
        if (c == '@') c = '.';
        
        // Check for dot or dot-like characters
        if (c == '.' || c == ',' || c == ' ' || c == '-' || c == '/' || c == '\\') {
            if (partLen > 0) {
                part[partLen] = '\0';
                
                // Check if this part matches a TLD
                if (dots > 0) {
                    for (int j = 0; COMMON_TLDS[j] != NULL; j++) {
                        if (strcmp(part, COMMON_TLDS[j]) == 0) {
                            return true;
                        }
                    }
                }
                
                dots++;
                partLen = 0;
                hasDot = true;
            }
            continue;
        }
        
        // Allow letters and numbers
        if (isalnum(c) || c == '-') {
            if (partLen < 255) {
                part[partLen++] = c;
                hasValidChar = true;
            }
        }
        // Reset on invalid characters
        else if (!isspace(c)) {
            partLen = 0;
            dots = 0;
        }
    }
    
    // Check last part
    if (partLen > 0) {
        part[partLen] = '\0';
        // Also check for 'lk' TLD specifically for implaza.lk
        if ((strcmp(part, "lk") == 0) && hasDot && hasValidChar) {
            return true;
        }
        for (int j = 0; COMMON_TLDS[j] != NULL; j++) {
            if (strcmp(part, COMMON_TLDS[j]) == 0 && hasDot && hasValidChar) {
                return true;
            }
        }
    }
    
    return false;
}

void CensorMessages_Init() {
    Plugin_Printf("IP and Domain Censor: init complete.\n");
}

char* CensorMessages(char* msg) {
    // First check if message contains whitelisted domain
    if (containsWhitelistedDomain(msg)) {
        return msg;  // Return original message without censoring
    }
    
    // Otherwise proceed with normal censoring
    if (hasIP(msg) || hasDomain(msg)) {
        // Censor the entire message
        for(int i = 0; msg[i]; i++) {
            msg[i] = '*';
        }
    }
    return msg;
}
