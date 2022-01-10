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

#include "medialibrary_smartalbum_operations.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS
{
    namespace Media
    {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "medialibrary_smart_oprn"};
        int32_t InsertAlbumInfoUtil(const ValuesBucket &valuesBucket, shared_ptr<RdbStore> rdbStore,
                                    const MediaLibrarySmartAlbumDb &smartAlbumDbOprn)
        {
            OHOS::HiviewDFX::HiLog::Error(LABEL, "HandleSmartAlbumOperations");
            ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
            return const_cast<MediaLibrarySmartAlbumDb &>(smartAlbumDbOprn).InsertSmartAlbumInfo(values, rdbStore);
        }

        // int32_t UpdateAlbumInfoUtil(const ValuesBucket &valuesBucket, const string &albumPath,
        //                             const string &albumNewName, shared_ptr<RdbStore> rdbStore, const MediaLibraryAlbumDb &albumDbOprn)
        // {
        //     int32_t retVal = DATA_ABILITY_FAIL;
        //     ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
        //     string newAlbumPath;

        //     if ((rdbStore == nullptr) || (albumPath.empty()) || (albumNewName.empty()))
        //     {
        //         return retVal;
        //     }

        //     if (albumNewName.at(0) == '.')
        //     {
        //         int32_t deletedRows = ALBUM_OPERATION_ERR;
        //         vector<string> whereArgs = {(albumPath.back() != '/' ? (albumPath + "/%") : (albumPath + "%")), albumPath};

        //         int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, "path LIKE ? OR path = ?", whereArgs);
        //         if (deleteResult != E_OK)
        //         {
        //             MEDIA_ERR_LOG("Delete rows failed");
        //         }
        //         return DATA_ABILITY_SUCCESS;
        //     }

        //     size_t slashIndex = albumPath.rfind("/");
        //     if (slashIndex != string::npos)
        //     {
        //         newAlbumPath = albumPath.substr(0, slashIndex) + "/" + albumNewName;
        //         values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, albumPath.substr(0, slashIndex));
        //     }

        //     values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
        //     values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED,
        //                    MediaLibraryDataAbilityUtils::GetAlbumDateModified(newAlbumPath));

        //     retVal = const_cast<MediaLibraryAlbumDb &>(albumDbOprn).UpdateAlbumInfo(values, rdbStore);
        //     if ((retVal == DATA_ABILITY_SUCCESS) && (!newAlbumPath.empty()))
        //     {
        //         // Update the path, relative path and album Name for internal files
        //         const std::string modifyAlbumInternalsStmt =
        //             "UPDATE MEDIALIBRARY_DATA SET path = replace(path, '" + albumPath + "/' , '" + newAlbumPath + "/'), " + "relative_path = replace(relative_path, '" + albumPath + "', '" + newAlbumPath + "'), " + "album_name = replace(album_name, '" + albumPath.substr(slashIndex + 1) + "', '" + albumNewName + "')" + "where path LIKE '" + albumPath + "/%'";

        //         auto ret = rdbStore->ExecuteSql(modifyAlbumInternalsStmt);
        //         CHECK_AND_PRINT_LOG(ret == 0, "Album update sql failed");
        //     }

        //     return retVal;
        // }

        // int32_t DeleteAlbumInfoUtil(const ValuesBucket &valuesBucket, int32_t albumId, const string &albumPath,
        //                             shared_ptr<RdbStore> rdbStore, const MediaLibraryAlbumDb &albumDbOprn)
        // {
        //     int32_t retVal;
        //     ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);

        //     retVal = const_cast<MediaLibraryAlbumDb &>(albumDbOprn).DeleteAlbumInfo(albumId, rdbStore);
        //     if ((retVal == DATA_ABILITY_SUCCESS) && (rdbStore != nullptr) && (!albumPath.empty()))
        //     {
        //         int32_t deletedRows = ALBUM_OPERATION_ERR;
        //         vector<string> whereArgs = {(albumPath.back() != '/' ? (albumPath + "/%") : (albumPath + "%"))};

        //         int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, "path LIKE ?", whereArgs);
        //         if (deleteResult != E_OK)
        //         {
        //             MEDIA_ERR_LOG("Delete rows failed");
        //         }
        //     }

        //     return retVal;
        // }

        int32_t MediaLibrarySmartAlbumOperations::HandleSmartAlbumOperations(const string &oprn, const ValuesBucket &valuesBucket,
                                                                        const shared_ptr<RdbStore> &rdbStore)
        {
            OHOS::HiviewDFX::HiLog::Error(LABEL, "HandleSmartAlbumOperations = %{public}s",oprn.c_str());
            ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
            MediaLibrarySmartAlbumDb smartAlbumDbOprn;
            int32_t errCode = DATA_ABILITY_FAIL;
            ValueObject valueObject;
            if (oprn == MEDIA_SMARTALBUMOPRN_CREATEALBUM)
            {
                errCode = InsertAlbumInfoUtil(values, rdbStore, smartAlbumDbOprn);
                OHOS::HiviewDFX::HiLog::Error(LABEL, "errCode = %{public}u",errCode);
            } else {
                // int32_t albumId = 0;
                // if (values.GetObject(MEDIA_DATA_DB_ID, valueObject))
                // {
                //     valueObject.GetInt(albumId);
                // }
                // string albumPath = MediaLibraryDataAbilityUtils::GetPathFromDb(to_string(albumId), rdbStore);
                // if (albumPath.empty())
                // {
                //     return errCode;
                // }

                if (oprn == MEDIA_SMARTALBUMOPRN_MODIFYALBUM)
                {
                    // string albumNewName = "";
                    // if (values.GetObject(SMARTALBUM_DB_NAME, valueObject))
                    // {
                    //     valueObject.GetString(albumNewName);
                    // }
                    //errCode = UpdateAlbumInfoUtil(values, albumPath, albumNewName, rdbStore, albumDbOprn);
                }
                else if (oprn == MEDIA_SMARTALBUMOPRN_DELETEALBUM)
                {
                    //errCode = DeleteAlbumInfoUtil(values, albumId, albumPath, rdbStore, albumDbOprn);
                }
            }

            return errCode;
        }
    } // namespace Media
} // namespace OHOS