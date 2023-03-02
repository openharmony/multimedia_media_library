/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_COLUMN_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_COLUMN_H_

#include <string>

namespace OHOS {
namespace Media {

class MediaColumn {
public:
    // Asset Base Parameter
    const static std::string MEDIA_ID;
    const static std::string MEDIA_URI;
    const static std::string MEDIA_FILE_PATH;
    const static std::string MEDIA_SIZE;
    const static std::string MEDIA_TITLE;
    const static std::string MEDIA_NAME;
    const static std::string MEDIA_MEDIA_TYPE;
    const static std::string MEDIA_MIME_TYPE;
    const static std::string MEDIA_OWNER_PACKAGE;
    const static std::string MEDIA_DEVICE_NAME;
    const static std::string MEDIA_THUMBNAIL;
    const static std::string MEDIA_ARTIST;

    // As set Parameter about time
    const static std::string MEDIA_DATE_MODIFIED;
    const static std::string MEDIA_DATE_ADDED;
    const static std::string MEDIA_DATE_TAKEN;
    const static std::string MEDIA_TIME_VISIT;
    const static std::string MEDIA_DURATION;
    const static std::string MEDIA_TIME_PENDING;
    const static std::string MEDIA_IS_FAV;
    const static std::string MEDIA_DATE_TRASHED;
    const static std::string MEDIA_DATE_DELETED;
    const static std::string MEDIA_HIDDEN;

    // Asset Parameter deperated
    const static std::string MEDIA_PARENT_ID;
    const static std::string MEDIA_RELATIVE_PATH;
};

class PhotoColumn : public MediaColumn {
public:
    // column only in PhotoTable
    const static std::string PHOTO_ORIENTATION;
    const static std::string PHOTO_LATITUDE;
    const static std::string PHOTO_LONGITUDE;
    const static std::string PHOTO_LCD;
    const static std::string PHOTO_HEIGHT;
    const static std::string PHOTO_WIDTH;

    // table name
    const static std::string PHOTOS_TABLE;

    // create PhotoTable sql
    const static std::string CREATE_PHOTO_TABLE;
};

class AudioColumn : public MediaColumn {
public:
    // column only in AudioTable
    const static std::string AUDIO_ALBUM;

    // table name
    const static std::string AUDIOS_TABLE;

    // create AudioTable sql
    const static std::string CREATE_AUDIO_TABLE;
};

class DocumentColumn : public MediaColumn {
public:
    // table name
    const static std::string DOCUMENTS_TABLE;

    // create DocumentTable sql
    const static std::string CREATE_DOCUMENT_TABLE;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_COLUMN_H_