/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_FILEMANAGEMENT_USERFILEMGR_TYPES_H
#define OHOS_FILEMANAGEMENT_USERFILEMGR_TYPES_H

#include <string>
#include <vector>
#include <tuple>

namespace OHOS {
namespace Media {
enum class ResultNapiType {
    TYPE_MEDIALIBRARY,
    TYPE_USERFILE_MGR,
    TYPE_NAPI_MAX
};

enum MediaType {
    MEDIA_TYPE_FILE,
    MEDIA_TYPE_IMAGE,
    MEDIA_TYPE_VIDEO,
    MEDIA_TYPE_AUDIO,
    MEDIA_TYPE_MEDIA,
    MEDIA_TYPE_ALBUM_LIST,
    MEDIA_TYPE_ALBUM_LIST_INFO,
    MEDIA_TYPE_ALBUM,
    MEDIA_TYPE_SMARTALBUM,
    MEDIA_TYPE_DEVICE,
    MEDIA_TYPE_REMOTEFILE,
    MEDIA_TYPE_NOFILE,
    MEDIA_TYPE_ALL,
};

enum class MediaTypeMaskInteger: std::uint32_t {
    BIT_IMAGEVIDEO = 0x01,
    BIT_AUDIO = 0x02,
    BIT_DOCUMENT = 0x04,
};

/* Constant definitions about media type mask */
constexpr size_t TYPE_MASK_STRING_SIZE = 3;
const std::string DEFAULT_TYPE_MASK = "";
const std::string URI_PARAM_KEY_TYPE = "type";
enum {
    TYPE_MASK_BIT_DEFAULT = '0',
    TYPE_MASK_BIT_SET = '1'
};

/*
 * The position in tuple is explained as below:
 * @POS_MEDIA_TYPE: The same as enum MediaType
 * @POS_TYPE_DESCRIPTION: Description of a MediaType in string, the same with interface "MediaType" in d.ts
 * @POS_TYPE_MASK_INTEGER：Media type bit mask in integer
 * @POS_TYPE_MASK_STRING_INDEX: Bit index of media type bit mask string
 *
 * A media type mask string is consist of three chars, as "000", each char stands one of MediaType.
 * The char with TYPE_MASK_STRING_INDEX of 0 stands MEDIA_TYPE_FILE,
 *                                         1 stands MEDIA_TYPE_AUDIO,
 *                                         2 stands MEDIA_TYPE_IMAGE or MEDIA_TYPE_VIDEO.
 * eg. If user specified a query condition with "MEDIA_TYPE_AUDIO", the type mask string would be "010",
 */
enum MEDIA_TYPE_TUPLE_INDEX {
    POS_MEDIA_TYPE = 0,
    POS_TYPE_DESCRIPTION,
    POS_TYPE_MASK_INTEGER,
    POS_TYPE_MASK_STRING_INDEX,
};
const std::vector<std::tuple<MediaType, std::string, MediaTypeMaskInteger, size_t>> MEDIA_TYPE_TUPLE_VEC = {
    std::make_tuple(MEDIA_TYPE_FILE,    "FILE",     MediaTypeMaskInteger::BIT_DOCUMENT,   0),
    std::make_tuple(MEDIA_TYPE_IMAGE,   "IMAGE",    MediaTypeMaskInteger::BIT_IMAGEVIDEO, 2),
    std::make_tuple(MEDIA_TYPE_VIDEO,   "VIDEO",    MediaTypeMaskInteger::BIT_IMAGEVIDEO, 2),
    std::make_tuple(MEDIA_TYPE_AUDIO,   "AUDIO",    MediaTypeMaskInteger::BIT_AUDIO,      1)
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_TYPES_H
