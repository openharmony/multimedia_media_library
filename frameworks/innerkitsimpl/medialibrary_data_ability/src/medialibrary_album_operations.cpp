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

#include "medialibrary_album_operations.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t InsertAlbumInfoUtil(const ValuesBucket &valuesBucket, const string &albumPath, shared_ptr<RdbStore> rdbStore,
    const MediaLibraryAlbumDb &albumDbOprn)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);

    string albumName;
    size_t index = albumPath.rfind('/');
    if (index != string::npos) {
        albumName = albumPath.substr(index + 1);
    }
    values.PutString(Media::MEDIA_DATA_DB_ALBUM_NAME, albumName);
    values.PutInt(Media::MEDIA_DATA_DB_MEDIA_TYPE, MediaType::MEDIA_TYPE_ALBUM);
    values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, albumPath.substr(0, index));

    struct stat statInfo {};
    if (stat(albumPath.c_str(), &statInfo) == 0) {
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime * SECONDS_TO_MILLISECONDS);
    }

    return const_cast<MediaLibraryAlbumDb &>(albumDbOprn).InsertAlbumInfo(values, rdbStore);
}

int32_t UpdateAlbumInfoUtil(const ValuesBucket &valuesBucket, const string &albumPath,
    const string &albumNewName, shared_ptr<RdbStore> rdbStore, const MediaLibraryAlbumDb &albumDbOprn)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    string newAlbumPath;

    size_t slashIndex = albumPath.rfind("/");
    if (slashIndex != string::npos) {
        newAlbumPath = albumPath.substr(0, slashIndex) + "/" + albumNewName;
    }
    values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, albumPath.substr(0, slashIndex));

    struct stat statInfo {};
    if (stat(newAlbumPath.c_str(), &statInfo) == 0) {
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime * SECONDS_TO_MILLISECONDS);
    }

    return const_cast<MediaLibraryAlbumDb &>(albumDbOprn).UpdateAlbumInfo(values, rdbStore);
}

int32_t MediaLibraryAlbumOperations::HandleAlbumOperations(const string &uri, const ValuesBucket &valuesBucket,
    const shared_ptr<RdbStore> &rdbStore)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    AlbumAsset albumAsset;
    MediaLibraryAlbumDb albumDbOprn;
    int32_t errCode = DATA_ABILITY_FAIL;
    ValueObject valueObject;

    size_t found = uri.rfind('/');
    if (found != string::npos) {
        string oprn = uri.substr(found + 1);
        if (oprn == MEDIA_ALBUMOPRN_CREATEALBUM) {
            string albumPath;
            values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject);
            valueObject.GetString(albumPath);

            albumAsset.SetAlbumPath(albumPath);

            bool retVal = albumAsset.CreateAlbumAsset();
            if (retVal == true) {
                errCode = InsertAlbumInfoUtil(values, albumPath, rdbStore, albumDbOprn);
            }
        } else if (oprn == MEDIA_ALBUMOPRN_MODIFYALBUM) {
            int32_t albumId;
            values.GetObject(MEDIA_DATA_DB_ID, valueObject);
            valueObject.GetInt(albumId);

            string albumNewName;
            values.GetObject(MEDIA_DATA_DB_ALBUM_NAME, valueObject);
            valueObject.GetString(albumNewName);

            albumAsset.SetAlbumName(albumNewName);

            string albumPath = albumDbOprn.GetAlbumPath(albumId, rdbStore);
            bool retVal = albumAsset.ModifyAlbumAsset(albumPath);
            if (retVal == true) {
                errCode = UpdateAlbumInfoUtil(values, albumPath, albumNewName, rdbStore, albumDbOprn);
            }
        } else if (oprn == MEDIA_ALBUMOPRN_DELETEALBUM) {
            int32_t albumId;
            values.GetObject(MEDIA_DATA_DB_ID, valueObject);
            valueObject.GetInt(albumId);

            string albumPath = albumDbOprn.GetAlbumPath(albumId, rdbStore);
            if (albumAsset.DeleteAlbumAsset(albumPath) == true) {
                errCode = albumDbOprn.DeleteAlbumInfo(albumId, rdbStore);
            }
        }
    }

    return errCode;
}
} // namespace Media
} // namespace OHOS