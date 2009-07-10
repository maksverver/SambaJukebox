#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <cassert>
#include <ctime>

#include "libsmbclient.h"
#include "id3/tag.h"
#include "id3/misc_support.h"
#include "sqlite3.h"
#include "openssl/md5.h"

#define SMB_WORKGROUP   "jukebox"
#define SMB_USERNAME    "jukebox"
#define SMB_PASSWORD    "jukebox"

static sqlite3 *db;
static sqlite3_stmt *insert_song_stmt;
static sqlite3_stmt *find_term_stmt;
static sqlite3_stmt *insert_term_stmt;
static sqlite3_stmt *insert_termocc_stmt;

static SMBCCTX *smbc_ctx;

void process(const std::string &url);

static void get_auth_data (const char *srv, const char *shr, char *wg,\
    int wglen, char *un, int unlen, char *pw, int pwlen)
{
    (void)srv, (void)shr; /* unused */
    /* printf("Authenticating to server \"%s\" share \"%s\"...\n", srv, shr); */
    std::strncpy(wg, SMB_WORKGROUP, wglen);
    std::strncpy(un, SMB_USERNAME, unlen);
    std::strncpy(pw, SMB_PASSWORD, pwlen);
}

static sqlite3_int64 get_term_id(const std::string &text)
{
    sqlite3_int64 res = -1;

    /* Search for an existing row in the Term table: */
    sqlite3_bind_text(find_term_stmt, 1, text.data(), text.size(), SQLITE_STATIC);
    if (sqlite3_step(find_term_stmt) == SQLITE_ROW)
        res = sqlite3_column_int64(find_term_stmt, 0);
    sqlite3_reset(find_term_stmt);

    if (res == -1)
    {
        /* Insert new row into the Term table: */
        sqlite3_bind_text(insert_term_stmt, 1, text.data(), text.size(), SQLITE_STATIC);
        int err = sqlite3_step(insert_term_stmt);
        assert(err == SQLITE_DONE);
        sqlite3_reset(insert_term_stmt);
        res = sqlite3_last_insert_rowid(db);
    }

    return res;
}

bool has_mp3_ext(const std::string &url)
{
    if (url.size() < 4) return false;
    char dot, em, pee, three;
    dot   = tolower(url[url.size() - 4]);
    em    = tolower(url[url.size() - 3]);
    pee   = tolower(url[url.size() - 2]);
    three = tolower(url[url.size() - 1]);
    return dot == '.' && em == 'm' && pee == 'p' && three == '3';
}

std::string parse_id3_field(const char *begin, size_t size)
{
    const char *end = begin + size;
    while (begin < end && begin[0] == ' ') ++begin;  // strip leading space
    end = std::find(begin, end, '\0');  // clip to terminating zero
    while (end > begin && end[-1] == ' ') --end;  // strip trailing space
    return std::string(begin, end);
}

static bool get_file_digest(int fd, off_t filesize, uchar digest[])
{
    char buf[8192];
    size_t len;

    if (filesize <= 8192)
    {
        /* Read entire file */
        if (smbc_lseek(fd, 0, SEEK_SET) != 0 ||
            smbc_read(fd, buf, filesize) != filesize)
            return false;
        len = filesize;
    }
    else
    {
        /* Read first 4KB + last 4KB: */
        if (smbc_lseek(fd, 0, SEEK_SET) != 0 ||
            smbc_read(fd, buf, 4096) != 4096 ||
            smbc_lseek(fd, filesize - 4096, SEEK_SET) != filesize - 4096 ||
            smbc_read(fd, buf + 4096, 4096) != 4096)
            return false;
        len = 8192;
    }

    return MD5((const uchar*)buf, len, digest) == digest;
}

/*
static std::string tohex(std::string data)
{
    std::string res;
    res.reserve(data.size()*2);
    for (std::string::const_iterator it = data.begin(); it != data.end(); ++it)
    {
        res += "0123456789abcdef"[((*it)&0xf0)>>4];
        res += "0123456789abcdef"[((*it)&0x0f)>>0];
    }
    return res;
}
*/

/* Converts text to a list of terms, as follows:
    - all non-alphanumeric characters are treated as separating whitespace
    - no empty terms are included
    - all letters are converted to lower case
*/
static std::vector<std::string> text_to_terms(const std::string &text)
{
    std::vector<std::string> terms;
    std::string term;
    std::string::const_iterator it = text.begin();
    do {
        if (it != text.end() && std::isalnum(*it))
        {
            term += std::tolower(*it);
        }
        else
        {
            if (!term.empty())
                terms.push_back(term);
            term.clear();
        }
    } while (it++ != text.end());
    return terms;
}

static void add_term_refs( sqlite3_int64 song_id,
                           int type, const std::string &text )
{
    std::vector<std::string> terms = text_to_terms(text);
    for (size_t pos = 0; pos < terms.size(); ++pos)
    {
        sqlite3_int64 term_id = get_term_id(terms[pos]);
        sqlite3_bind_int64(insert_termocc_stmt, 1, term_id);
        sqlite3_bind_int64(insert_termocc_stmt, 2, song_id);
        sqlite3_bind_int64(insert_termocc_stmt, 3, type);
        sqlite3_bind_int64(insert_termocc_stmt, 4, (sqlite3_int64)pos);
        int err = sqlite3_step(insert_termocc_stmt);
        assert(err == SQLITE_DONE);
        sqlite3_reset(insert_termocc_stmt);
    }
}

void process_mp3(const std::string &url, off_t filesize)
{
    const time_t now = std::time(NULL);
    int fd = 0;
    uchar digest[MD5_DIGEST_LENGTH];
    uchar tagheader[ID3_TAGHEADERSIZE];
    uchar *tagbuffer = NULL;

    /* Tag data: */
    std::string title, artist, album;
    int trackno = 0, year = 0, tagtype = 0;

    /* If file is too small, ignore it: */
    if (filesize < 65536) return;

    fd = smbc_open(url.c_str(), O_RDONLY, 0);
    if (fd < 0)
    {
        printf("Couldn't open \"%s\" for reading!\n", url.c_str());
        return;
    }

    if (!get_file_digest(fd, filesize, digest))
    {
        printf("Couldn't get digest of file \"%s\"!\n", url.c_str());
    }

    if (smbc_lseek(fd, 0, SEEK_SET) != 0 ||
        smbc_read(fd, tagheader, ID3_TAGHEADERSIZE) != ID3_TAGHEADERSIZE)
    {
        printf("Couldn't read tag header from \"%s\"!\n", url.c_str());
        goto failed;
    }

    int32 tagsize;
    if ((tagsize = ID3_IsTagHeader(tagheader)) >= 0)
    {
        /* Read ID3v2 header (at the start of the file) */
        ID3_Tag tag;
        tagbuffer = new uchar[tagsize];
        assert(tagbuffer != NULL);

        if (smbc_read(fd, tagbuffer, tagsize) != tagsize)
        {
            printf("Couldn't read full tag from file \"%s\"!\n", url.c_str());
            goto failed;
        }

        if (tag.Parse(tagheader, tagbuffer) == 0)
        {
            printf("Couldn't parse tag for file \"%s\"!\n", url.c_str());
            goto failed;
        }

        /* Succesfully parsed ID3v2 tag */
        char *str;
        if ((str = ID3_GetTitle(&tag)) != NULL)
        {
            title = str;
            ID3_FreeString(str);
        }
        if ((str = ID3_GetArtist(&tag)) != NULL)
        {
            artist = str;
            ID3_FreeString(str);
        }
        if ((str = ID3_GetAlbum(&tag)) != NULL)
        {
            album = str;
            ID3_FreeString(str);
        }
        if ((str = ID3_GetYear(&tag)) != NULL)
        {
            year = atoi(str);
            ID3_FreeString(str);
        }
        trackno = (int)ID3_GetTrackNum(&tag);
        tagtype = 2;
    }
    else
    {
        tagbuffer = new uchar[128];
        if (filesize < 128 ||
            smbc_lseek(fd, filesize - 128, SEEK_SET) != filesize - 128 ||
            smbc_read(fd, tagbuffer, 128) != 128 ||
            tagbuffer[0] != 'T' || tagbuffer[1] != 'A' || tagbuffer[2] != 'G')
        {
            printf("File \"%s\" doesn't have a tag.\n", url.c_str());
            goto failed;
        }

        /*  ID3 v1/v1.1 layout

            offset  size    contents
              0       3     "TAG"
              3      30     title
             33      30     artist
             63      30     album
             93       4     year
             97      28/30  comment (28 if genre is present)
            125       0     0  (if track num is present
            126       1     1  (if track num is present)
            127       1     genre
            128       0     EOF
        */

        title   = parse_id3_field((char*)tagbuffer +  3, 30);
        artist  = parse_id3_field((char*)tagbuffer + 33, 30);
        album   = parse_id3_field((char*)tagbuffer + 63, 30);
        year    = atoi(parse_id3_field((char*)tagbuffer + 93, 4).c_str());
        trackno = tagbuffer[125] == 0 && tagbuffer[126] != 0xff ? (int)tagbuffer[126] : 0;
        tagtype = 1;
    }

    /* We have a tag; store the song in the database: */
    sqlite3_stmt *s;
    s = insert_song_stmt;
    sqlite3_bind_text(s, 1, url.data(), url.size(), SQLITE_STATIC);
    sqlite3_bind_int (s, 2, (int)now);
    if (tagtype != 0)
        sqlite3_bind_int (s, 3, tagtype);
    if (!title.empty())
        sqlite3_bind_text(s, 4, title.data(), url.size(), SQLITE_STATIC);
    if (!artist.empty())
        sqlite3_bind_text(s, 5, artist.data(), artist.size(), SQLITE_STATIC);
    if (!album.empty())
        sqlite3_bind_text(s, 6, album.data(), album.size(), SQLITE_STATIC);
    if (trackno > 0)
        sqlite3_bind_int (s, 7, trackno);
    if (year > 1900 && year <= 9999)
        sqlite3_bind_int (s, 8, year);
    sqlite3_bind_int (s,  9, filesize);
    sqlite3_bind_blob(s, 10, digest, sizeof(digest), SQLITE_STATIC);
    if (sqlite3_step(s) != SQLITE_DONE)
        printf("Couldn't store entry for file \"%s\"!\n", url.c_str());
    sqlite3_reset(s);

    /* Add term references for this song */
    sqlite3_int64 song_id;
    song_id = sqlite3_last_insert_rowid(db);
    add_term_refs(song_id, 1, title);
    add_term_refs(song_id, 2, artist);
    add_term_refs(song_id, 3, album);

failed:
    smbc_close(fd);
    delete[] tagbuffer;
}

void process_dir(const std::string &url)
{
    /* printf("Listing \"%s\"...\n", url.c_str()); */

    int dh = smbc_opendir(url.c_str());
    if (dh < 0)
    {
        printf("Couldn't open directory \"%s\"!\n", url.c_str());
    }
    else
    {
        struct smbc_dirent *de;
        while ((de = smbc_readdir(dh)) != NULL)
        {
            if (de->name[0] != '.') process(url + '/' + de->name);
        }
        smbc_closedir(dh);
    }
}

void process(const std::string &url)
{
    struct stat st;
    if (smbc_stat(url.c_str(), &st) != 0)
    {
        printf("Couldn't stat \"%s\"\n", url.c_str());
        return;
    }

    if (S_ISDIR(st.st_mode))
    {
        process_dir(url);
    }
    else
    if (S_ISREG(st.st_mode) && has_mp3_ext(url))
    {
        process_mp3(url.c_str(), st.st_size);
    }
}

static bool db_initialize(const char *path)
{
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return false;

    int res;
    res = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO Song (url, indexed, tagtype, title, artist, album, track, year, filesize, digest)"
        " VALUES ($url, $indexed, $tagtype, $title, $artist, $album, $track, $year, $filesize, $digest)",
        -1, &insert_song_stmt, NULL);
    assert(res == SQLITE_OK);

    res = sqlite3_prepare_v2(db, "SELECT term_id FROM Term WHERE text=$text",
        -1, &find_term_stmt, NULL);
    assert(res == SQLITE_OK);

    res = sqlite3_prepare_v2(db, "INSERT INTO Term (text) VALUES ($text)",
        -1, &insert_term_stmt, NULL);
    assert(res == SQLITE_OK);

    res = sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO TermOcc (term_id, song_id, type, pos)"
        " VALUES ($term_id, $song_id, $type, $pos)",
        -1, &insert_termocc_stmt, NULL);
    assert(res == SQLITE_OK);

    res = sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    assert(res == SQLITE_OK);

    return true;
}

static void db_finalize()
{
    int res = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    assert(res == SQLITE_OK);

    sqlite3_finalize(insert_song_stmt);
    sqlite3_finalize(find_term_stmt);
    sqlite3_finalize(insert_term_stmt);
    sqlite3_finalize(insert_termocc_stmt);
    sqlite3_close(db);
    db = NULL;
}

static bool smbc_initialize()
{
    int res = smbc_init(&get_auth_data, 0);
    if (res != 0) return false;

    smbc_ctx = smbc_new_context();
    smbc_init_context(smbc_ctx);
    smbc_setOptionUrlEncodeReaddirEntries(smbc_ctx, 1);
    smbc_set_context(smbc_ctx);

    return true;
}

static void smbc_finalize()
{
    smbc_set_context(NULL);
    smbc_free_context(smbc_ctx, 1);
    smbc_ctx = NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: indexer <url> <database>\n");
        return 0;
    }

    if (!db_initialize(argv[2]))
    {
        printf("Couldn't open database \"%s\"!\n", argv[2]);
        return 1;
    }

    if (!smbc_initialize())
    {
        printf("Couldn't initialize SMB client library!\n");
        return 1;
    }

    process(argv[1]);

    smbc_finalize();
    db_finalize();

    return 0;
}
