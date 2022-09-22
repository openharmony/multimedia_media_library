/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sys/stat.h>

#include "medialibrary_type_const.h"
#include "media_scanner_const.h"

namespace OHOS {
namespace Media {
enum ErrorCodes {
    ERR_FAIL = -1,
    ERR_SUCCESS,
    ERR_EMPTY_ARGS,
    ERR_NOT_ACCESSIBLE,
    ERR_INCORRECT_PATH,
    ERR_MEM_ALLOC_FAIL,
    ERR_MIMETYPE_NOTSUPPORT,
    ERR_SCAN_NOT_INIT
};

const int32_t MAX_BATCH_SIZE = 5;

constexpr int32_t UNKNOWN_ID = -1;

// Const for File Metadata defaults
const std::string FILE_PATH_DEFAULT = "";
const std::string FILE_NAME_DEFAULT = "";
const int64_t FILE_SIZE_DEFAULT = 0;
const std::string URI_DEFAULT = "";
const int64_t FILE_DATE_ADDED_DEFAULT = 0;
const int64_t FILE_DATE_MODIFIED_DEFAULT = 0;
const MediaType FILE_MEDIA_TYPE_DEFAULT = MEDIA_TYPE_FILE;
const int32_t FILE_ID_DEFAULT = 0;
const std::string FILE_EXTENSION_DEFAULT = "";

const int32_t FILE_DURATION_DEFAULT = 0;
const std::string FILE_TITLE_DEFAULT = "";
const std::string FILE_ARTIST_DEFAULT = "";
const int32_t FILE_HEIGHT_DEFAULT = 0;
const int32_t FILE_WIDTH_DEFAULT = 0;
const int32_t FILE_ALBUM_ID_DEFAULT = 0;
const std::string FILE_ALBUM_NAME_DEFAULT = "";
const int32_t FILE_ORIENTATION_DEFAULT = 0;
const std::string FILE_RELATIVE_PATH_DEFAULT = "";
const std::string FILE_RECYCLE_PATH_DEFAULT = "";
const int64_t FILE_DATE_TAKEN_DEFAULT = 0;
const double FILE_LONGITUDE_DEFAULT = 0;
const double FILE_LATITUDE_DEFAULT = 0;

const std::string DEFAULT_AUDIO_MIME_TYPE = "audio/*";
const std::string DEFAULT_VIDEO_MIME_TYPE = "video/*";
const std::string DEFAULT_IMAGE_MIME_TYPE = "image/*";
const std::string DEFAULT_FILE_MIME_TYPE = "file/*";

static std::vector<std::string> EXTRACTOR_SUPPORTED_MIME = {
    DEFAULT_AUDIO_MIME_TYPE,
    DEFAULT_VIDEO_MIME_TYPE,
    DEFAULT_IMAGE_MIME_TYPE
};

static const std::unordered_map<std::string, std::string> SUPPORTED_EXTN_MAP = {
    /** Supported image types */
    {IMAGE_CONTAINER_TYPE_BMP, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_BM, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_GIF, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_JPG, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_JPEG, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_JPE, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_PNG, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_WEBP, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_RAW, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_SVG, DEFAULT_IMAGE_MIME_TYPE},
    {IMAGE_CONTAINER_TYPE_HEIF, DEFAULT_IMAGE_MIME_TYPE},
    /** Supported video container types */
    {VIDEO_CONTAINER_TYPE_MP4, DEFAULT_VIDEO_MIME_TYPE},
    {VIDEO_CONTAINER_TYPE_3GP, DEFAULT_VIDEO_MIME_TYPE},
    {VIDEO_CONTAINER_TYPE_MPG, DEFAULT_VIDEO_MIME_TYPE},
    {VIDEO_CONTAINER_TYPE_MOV, DEFAULT_VIDEO_MIME_TYPE},
    {VIDEO_CONTAINER_TYPE_WEBM, DEFAULT_VIDEO_MIME_TYPE},
    {VIDEO_CONTAINER_TYPE_MKV, DEFAULT_VIDEO_MIME_TYPE},
    {AUDIO_CONTAINER_TYPE_AAC, DEFAULT_AUDIO_MIME_TYPE},
    {AUDIO_CONTAINER_TYPE_MP3, DEFAULT_AUDIO_MIME_TYPE},
    {AUDIO_CONTAINER_TYPE_FLAC, DEFAULT_AUDIO_MIME_TYPE},
    {AUDIO_CONTAINER_TYPE_WAV, DEFAULT_AUDIO_MIME_TYPE},
    {AUDIO_CONTAINER_TYPE_OGG, DEFAULT_AUDIO_MIME_TYPE},
    {"7z", "application/x-7z-compressed"},
    {"bz", "application/x-bzip"},
    {"bz2", "application/x-bzip2"},
    {"cer", "application/pkix-cert"},
    {"clp", "application/x-msclip"},
    {"crl", "application/pkix-crl"},
    {"css", "text/css"},
    {"csv", "text/csv"},
    {"der", "application/x-x509-ca-cert"},
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"exe", "application/x-msdownload"},
    {"gtar", "application/x-gtar"},
    {"gz", "application/gzip"},
    {"html", "text/html"},
    {"ics", "text/calendar"},
    {"ipfix", "application/ipfix"},
    {"jar", "application/java-archive"},
    {"json", "application/json"},
    {"mdb", "application/x-msaccess"},
    {"nsf", "application/vnd.lotus-notes"},
    {"odb", "application/vnd.oasis.opendocument.database"},
    {"odc", "application/vnd.oasis.opendocument.chart"},
    {"odp", "application/vnd.oasis.opendocument.presentation"},
    {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {"odt", "application/vnd.oasis.opendocument.text"},
    {"p10", "application/pkcs10"},
    {"p12", "application/x-pkcs12"},
    {"p7b", "application/x-pkcs7-certificates"},
    {"p7m", "application/pkcs7-mime"},
    {"p7r", "application/x-pkcs7-certreqresp"},
    {"p7s", "application/pkcs7-signature"},
    {"p8", "application/pkcs8"},
    {"pdf", "application/pdf"},
    {"pki", "application/pkixcmp"},
    {"pkipath", "application/pkix-pkipath"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"rar", "application/x-rar-compressed"},
    {"rss", "application/rss+xml"},
    {"rtf", "application/rtf"},
    {"rtx", "text/richtext"},
    {"sxc", "application/vnd.sun.xml.calc"},
    {"sxg", "application/vnd.sun.xml.writer.global"},
    {"sxi", "application/vnd.sun.xml.impress"},
    {"sxw", "application/vnd.sun.xml.writer"},
    {"tar", "application/x-tar"},
    {"texinfo", "application/x-texinfo"},
    {"torrent", "application/x-bittorrent"},
    {"txt", "text/plain"},
    {"vcf", "text/x-vcard"},
    {"vcs", "text/x-vcalendar"},
    {"vsd", "application/vnd.visio"},
    {"vsdx", "application/vnd.visio2013"},
    {"vxml", "application/voicexml+xml"},
    {"wml", "text/vnd.wap.wml"},
    {"wmls", "text/vnd.wap.wmlscript"},
    {"wps", "application/vnd.ms-works"},
    {"wri", "application/x-mswrite"},
    {"xdf", "application/xcap-diff+xml"},
    {"xhtml", "application/xhtml+xml"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"xml", "application/xml"},
    {"xps", "application/vnd.ms-xpsdocument"},
    {"yaml", "text/yaml"},
    {"zip", "application/zip"},
};

class ScannerUtils {
public:
    ScannerUtils();
    ~ScannerUtils();

    static bool IsExists(const std::string &path);
    static std::string GetFileNameFromUri(const std::string &path);
    static std::string GetFileExtensionFromFileUri(const std::string &path);
    static std::string GetMimeTypeFromExtension(const std::string &extension);
    static std::string GetParentPath(const std::string &path);
    static bool IsFileHidden(const std::string &path);
    static bool IsDirectory(const std::string &path);
    static MediaType GetMediatypeFromMimetype(const std::string &mimetype);
    static void GetRootMediaDir(std::string &dir);
    static std::string GetFileTitle(const std::string &displayName);
    static bool IsDirHiddenRecursive(const std::string &path);
    static bool IsDirHidden(const std::string &path);
    static void InitSkipList();
    static bool CheckSkipScanList(const std::string &path);

private:
    static std::vector<size_t> skipList_;
};
} // namespace Media
} // namespace OHOS

#endif // SCANNER_UTILS_H
