/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_mimetype_test.h"

#include <algorithm>
#include <thread>
#include "medialibrary_errno.h"
#include "media_log.h"
#include "mimetype_utils.h"

using std::string;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

const std::map<string, string> g_testExt2MimeType = {
    { "wrf", "video/x-webex" },
    { "mov", "video/quicktime" },
    { "m4v", "video/mp4" },
    { "f4v", "video/mp4" },
    { "mp4v", "video/mp4" },
    { "mpeg4", "video/mp4" },
    { "mp4", "video/mp4" },
    { "m2ts", "video/mp2t" },
    { "mts", "video/mp2t" },
    { "3gpp2", "video/3gpp2" },
    { "3gp2", "video/3gpp2" },
    { "3g2", "video/3gpp2" },
    { "3gpp", "video/3gpp" },
    { "3gp", "video/3gpp" },
    { "vcf", "text/x-vcard" },
    { "cpp", "text/x-c++src" },
    { "c++", "text/x-c++src" },
    { "cxx", "text/x-c++src" },
    { "cc", "text/x-c++src" },
    { "hpp", "text/x-c++hdr" },
    { "h++", "text/x-c++hdr" },
    { "hxx", "text/x-c++hdr" },
    { "hh", "text/x-c++hdr" },
    { "html", "text/html" },
    { "htm", "text/html" },
    { "shtml", "text/html" },
    { "md", "text/markdown" },
    { "markdown", "text/markdown" },
    { "java", "text/x-java" },
    { "py", "text/x-python" },
    { "ts", "video/mp2ts" },
    { "rtf", "text/rtf" },
    { "pef", "image/x-pentax-pef" },
    { "nrw", "image/x-nikon-nrw" },
    { "raf", "image/x-fuji-raf" },
    { "jpg", "image/jpeg" },
    { "jpeg", "image/jpeg" },
    { "jpe", "image/jpeg"},
    { "raw", "image/x-dcraw" },
    { "cur", "image/ico" },
    { "heif", "image/heif" },
    { "hif", "image/heif" },
    { "prc", "application/x-mobipocket-ebook" },
    { "mobi", "application/x-mobipocket-ebook" },
    { "bmp", "image/bmp" },
    { "bm", "image/bmp" },
    { "srt", "application/x-subrip" },
    { "phps", "text/text" },
    { "m3u", "text/text" },
    { "m3u8", "text/text" },
    { "css", "text/css" },
    { "webarchivexml", "application/x-webarchive-xml" },
    { "stl", "application/vnd.ms-pki.stl" },
    { "pcf", "application/x-font" },
    { "imy", "audio/imelody" },
    { "avif", "image/avif" },
    { "vor", "application/vnd.stardivision.writer" },
    { "pot", "application/vnd.ms-powerpoint" },
    { "csv", "text/comma-separated-values" },
    { "webarchive", "application/x-webarchive" },
    { "png", "image/png" },
    { "ttml", "application/ttml+xml" },
    { "dfxp", "application/ttml+xml" },
    { "webp", "image/webp" },
    { "pgp", "application/pgp-signature" },
    { "dng", "image/x-adobe-dng" },
    { "p12", "application/x-pkcs12" },
    { "pfx", "application/x-pkcs12" },
    { "mka", "audio/x-matroska" },
    { "wpl", "application/vnd.ms-wpl" },
    { "webm", "video/webm" },
    { "sdp", "application/sdp" },
    { "ra", "audio/x-pn-realaudio" },
    { "gif", "image/gif" },
    { "smf", "audio/sp-midi" },
    { "ogg", "audio/ogg" },
    { "mp3", "audio/mpeg" },
    { "mp2", "audio/mpeg" },
    { "mp1", "audio/mpeg" },
    { "mpa", "audio/mpeg" },
    { "m4r", "audio/mpeg" },
    { "lrc", "application/lrc" },
    { "crt", "application/x-x509-ca-cert" },
    { "der", "application/x-x509-ca-cert" },
    { "heics", "image/heic-sequence" },
    { "heifs", "image/heic-sequence" },
    { "flac", "audio/flac" },
    { "epub", "application/epub+zip" },
    { "3ga", "audio/3gpp" },
    { "mxmf", "audio/mobile-xmf" },
    { "rss", "application/rss+xml" },
    { "h264", "video/H264" },
    { "heic", "image/heic" },
    { "wav", "audio/wav" },
    { "aac", "audio/aac" },
    { "adts", "audio/aac" },
    { "adt", "audio/aac" },
    { "snd", "audio/basic" },
    { "xml", "text/xml" },
    { "rtttl", "audio/midi" },
    { "xmf", "audio/midi" },
    { "rtx", "audio/midi" },
    { "yt", "video/vnd.youtube.yt" },
    { "arw", "image/x-sony-arw" },
    { "ico", "image/x-icon" },
    { "m3u", "audio/mpegurl" },
    { "smil", "application/smil+xml" },
    { "mpeg", "video/mpeg" },
    { "mpeg2", "video/mpeg" },
    { "mpv2", "video/mpeg" },
    { "mp2v", "video/mpeg" },
    { "m2v", "video/mpeg" },
    { "m2t", "video/mpeg" },
    { "mpeg1", "video/mpeg" },
    { "mpv1", "video/mpeg" },
    { "mp1v", "video/mpeg" },
    { "m1v", "video/mpeg" },
    { "mpg", "video/mpeg" },
    { "amr", "audio/amr" },
    { "mkv", "video/x-matroska" },
    { "mp3", "audio/x-mpeg" },
    { "rw2", "image/x-panasonic-rw2" },
    { "svg", "image/svg+xml" },
    { "ac3", "audio/ac3" },
    { "a52", "audio/ac3" },
    { "m4a", "audio/mp4" },
    { "m4b", "audio/mp4" },
    { "m4p", "audio/mp4" },
    { "f4a", "audio/mp4" },
    { "f4b", "audio/mp4" },
    { "f4p", "audio/mp4" },
    { "diff", "text/plain" },
    { "po", "text/plain" },
    { "txt", "text/plain" },
    { "srw", "image/x-samsung-srw" },
    { "pem", "application/x-pem-file" },
    { "cer", "application/pkix-cert" },
    { "json", "application/json" },
    { "js", "application/javascript" },
    { "rar", "application/rar" },
    { "zip", "application/zip" },
    { "pdf", "application/pdf" },
    { "doc", "application/msword" },
    { "xls", "application/ms-excel" },
    { "ppt", "application/vnd.ms-powerpoint" },
    { "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    { "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
    { "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" }
};

const std::map<string, MediaType> g_testMimeType2MediaType = {
    { "application/epub+zip", MEDIA_TYPE_FILE },
    { "application/lrc", MEDIA_TYPE_FILE },
    { "application/pkix-cert", MEDIA_TYPE_FILE },
    { "application/rss+xml", MEDIA_TYPE_FILE },
    { "application/sdp", MEDIA_TYPE_FILE },
    { "application/smil+xml", MEDIA_TYPE_FILE },
    { "application/ttml+xml", MEDIA_TYPE_FILE },
    { "application/vnd.ms-pki.stl", MEDIA_TYPE_FILE },
    { "application/vnd.ms-powerpoint", MEDIA_TYPE_FILE },
    { "application/vnd.ms-wpl", MEDIA_TYPE_FILE },
    { "application/vnd.stardivision.writer", MEDIA_TYPE_FILE },
    { "application/vnd.youtube.yt", MEDIA_TYPE_FILE },
    { "application/x-font", MEDIA_TYPE_FILE },
    { "application/x-mobipocket-ebook", MEDIA_TYPE_FILE },
    { "application/x-pem-file", MEDIA_TYPE_FILE },
    { "application/x-pkcs12", MEDIA_TYPE_FILE },
    { "application/x-subrip", MEDIA_TYPE_FILE },
    { "application/x-webarchive", MEDIA_TYPE_FILE },
    { "application/x-webarchive-xml", MEDIA_TYPE_FILE },
    { "application/pgp-signature", MEDIA_TYPE_FILE },
    { "application/x-x509-ca-cert", MEDIA_TYPE_FILE },
    { "audio/3gpp", MEDIA_TYPE_AUDIO },
    { "audio/ac3", MEDIA_TYPE_AUDIO },
    { "audio/amr", MEDIA_TYPE_AUDIO },
    { "audio/imelody", MEDIA_TYPE_AUDIO },
    { "audio/midi", MEDIA_TYPE_AUDIO },
    { "audio/mobile-xmf", MEDIA_TYPE_AUDIO },
    { "audio/mp4", MEDIA_TYPE_AUDIO },
    { "audio/mpegurl", MEDIA_TYPE_AUDIO },
    { "audio/sp-midi", MEDIA_TYPE_AUDIO },
    { "audio/x-matroska", MEDIA_TYPE_AUDIO },
    { "audio/x-pn-realaudio", MEDIA_TYPE_AUDIO },
    { "audio/x-mpeg", MEDIA_TYPE_AUDIO },
    { "audio/aac", MEDIA_TYPE_AUDIO },
    { "audio/basic", MEDIA_TYPE_AUDIO },
    { "audio/flac", MEDIA_TYPE_AUDIO },
    { "audio/mpeg", MEDIA_TYPE_AUDIO },
    { "audio/wav", MEDIA_TYPE_AUDIO },
    { "audio/ogg", MEDIA_TYPE_AUDIO },
    { "image/gif", MEDIA_TYPE_IMAGE },
    { "image/heic", MEDIA_TYPE_IMAGE },
    { "image/heic-sequence", MEDIA_TYPE_IMAGE },
    { "image/bmp", MEDIA_TYPE_IMAGE },
    { "image/heif", MEDIA_TYPE_IMAGE },
    { "image/avif", MEDIA_TYPE_IMAGE },
    { "image/ico", MEDIA_TYPE_IMAGE },
    { "image/webp", MEDIA_TYPE_IMAGE },
    { "image/x-adobe-dng", MEDIA_TYPE_IMAGE },
    { "image/x-fuji-raf", MEDIA_TYPE_IMAGE },
    { "image/x-icon", MEDIA_TYPE_IMAGE },
    { "image/x-nikon-nrw", MEDIA_TYPE_IMAGE },
    { "image/x-panasonic-rw2", MEDIA_TYPE_IMAGE },
    { "image/x-pentax-pef", MEDIA_TYPE_IMAGE },
    { "image/x-samsung-srw", MEDIA_TYPE_IMAGE },
    { "image/x-sony-arw", MEDIA_TYPE_IMAGE },
    { "image/x-dcraw", MEDIA_TYPE_IMAGE},
    { "image/jpeg", MEDIA_TYPE_IMAGE },
    { "image/png", MEDIA_TYPE_IMAGE },
    { "image/svg+xml", MEDIA_TYPE_IMAGE },
    { "video/3gpp2", MEDIA_TYPE_VIDEO },
    { "video/3gpp", MEDIA_TYPE_VIDEO },
    { "video/mp4", MEDIA_TYPE_VIDEO },
    { "video/mp2t", MEDIA_TYPE_VIDEO },
    { "video/mp2ts", MEDIA_TYPE_VIDEO },
    { "video/vnd.youtube.yt", MEDIA_TYPE_VIDEO },
    { "video/x-webex", MEDIA_TYPE_VIDEO },
    { "video/mpeg", MEDIA_TYPE_VIDEO },
    { "video/quicktime", MEDIA_TYPE_VIDEO },
    { "video/x-matroska", MEDIA_TYPE_VIDEO },
    { "video/webm", MEDIA_TYPE_VIDEO },
    { "video/H264", MEDIA_TYPE_VIDEO },
    { "text/comma-separated-values", MEDIA_TYPE_FILE },
    { "text/plain", MEDIA_TYPE_FILE },
    { "text/rtf", MEDIA_TYPE_FILE },
    { "text/text", MEDIA_TYPE_FILE },
    { "text/xml", MEDIA_TYPE_FILE },
    { "text/x-vcard", MEDIA_TYPE_FILE },
    { "text/x-c++hdr", MEDIA_TYPE_FILE },
    { "text/x-c++src", MEDIA_TYPE_FILE }
};

void MimeTypeTest::SetUpTestCase() {}

void MimeTypeTest::TearDownTestCase() {}
void MimeTypeTest::SetUp() {}
void MimeTypeTest::TearDown(void) {}

HWTEST_F(MimeTypeTest, MimeTypeTest_InitMimeTypeMap_Test_001, TestSize.Level1)
{
    auto ret = MimeTypeUtils::InitMimeTypeMap();
    ASSERT_EQ(ret, E_OK);
}

HWTEST_F(MimeTypeTest, MimeTypeTest_GetMimeTypeFromExtension_Test_001, TestSize.Level1)
{
    int32_t ret;
    if (MimeTypeUtils::IsMimeTypeMapEmpty()) {
        ret = MimeTypeUtils::InitMimeTypeMap();
    } else {
        ret = E_OK;
    }
    ASSERT_EQ(ret, E_OK);
    for (const auto& item : g_testExt2MimeType) {
        auto mimeType = MimeTypeUtils::GetMimeTypeFromExtension(item.first);
        ASSERT_EQ(mimeType, item.second);
        string upperExtension = item.first;
        std::transform(upperExtension.begin(), upperExtension.end(), upperExtension.begin(), ::toupper);
        mimeType = MimeTypeUtils::GetMimeTypeFromExtension(upperExtension);
        ASSERT_EQ(mimeType, item.second);
    }
}

HWTEST_F(MimeTypeTest, MimeTypeTest_GetMediaTypeFromMimeType_Test_001, TestSize.Level1)
{
    int32_t ret;
    if (MimeTypeUtils::IsMimeTypeMapEmpty()) {
        ret = MimeTypeUtils::InitMimeTypeMap();
    } else {
        ret = E_OK;
    }
    ASSERT_EQ(ret, E_OK);
    for (const auto& item : g_testMimeType2MediaType) {
        auto mediaType = MimeTypeUtils::GetMediaTypeFromMimeType(item.first);
        ASSERT_EQ(mediaType, item.second);
    }
}
} // namespace Media
} // namespace OHOS