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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LIBRARY_MANAGER_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LIBRARY_MANAGER_H_

#include <cerrno>
#include <iostream>
#include <variant>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <securec.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ability.h"
#include "ability_context.h"
#include "ability_loader.h"
#include "album_asset.h"
#include "abs_shared_result_set.h"
#include "context.h"
#include "data_ability_helper.h"
#include "data_ability_predicates.h"
#include "data_ability_observer_stub.h"
#include "file_asset.h"
#include "fetch_result.h"
#include "media_data_ability_const.h"
#include "media_volume.h"
#include "uri.h"
#include "values_bucket.h"
#include "datashare_helper.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::DataShare;

/**
 * @brief Structure for defining the condition for fetching of files and albums
 *
 * @since 1.0
 * @version 1.0
 */
struct MediaFetchOptions {
    /**
     * @brief The Query condition based on which to fetch the files/albums
     */
    string selections;

    /**
     * @brief List of values for columns mentioned in the selections query condition
     */
    vector<string> selectionArgs;

    /**
     * @brief The column based on which the output will be sorted in ascending order
     */
    string order;
};

/**
 * @brief Interface for accessing all the File operation and AlbumAsset operation APIs
 *
 * @since 1.0
 * @version 1.0
 */
class MediaLibraryManager {
public:
    MediaLibraryManager() = default;
    virtual ~MediaLibraryManager() = default;

    /**
     * @brief Returns the Media Library Manager Instance
     *
     * @return Returns the Media Library Manager Instance
     * @since 1.0
     * @version 1.0
     */
    static MediaLibraryManager *GetMediaLibraryManager();

    /**
     * @brief Initializes the environment for Media Library Manager
     *
     * @param context The Ability context required for calling Data Ability Helper APIs
     * @since 1.0
     * @version 1.0
     */
    void InitMediaLibraryManager(const shared_ptr<AppExecFwk::Context> context);

    /**
     * @brief Initializes the environment for Media Library Manager
     *
     * @param context The Ability context required for calling Data Ability Helper APIs
     * @since 1.0
     * @version 1.0
     */
    void InitMediaLibraryManager(const sptr<IRemoteObject> &token);

    /**
     * @brief Obtain a FetchResult object from which File Assets can be obtained
     *
     * @param fetchOptions Condition for obtaining the list of file assets
     * @return a FetchResult object which has metadata for a list of files
     * @since 1.0
     * @version 1.0
     */
    unique_ptr<FetchResult> GetFileAssets(const MediaFetchOptions &fetchOptions);

    /**
     * @brief Get the list of albums based on certain conditions
     *
     * @param fetchOptions Condition for obtaining the list of Albums
     * @return a vector of albums along with their metadata
     * @since 1.0
     * @version 1.0
     */
    vector<unique_ptr<AlbumAsset>> GetAlbums(const MediaFetchOptions &fetchOptions);

    /**
     * @brief Create a new file
     *
     * @param fileAsset a FileAsset which has mediatype and filePath information
     * @return uri for the created file
     * @since 1.0
     * @version 1.0
     */
    string CreateAsset(const FileAsset &fileAsset);

    /**
     * @brief Modify an existing file
     *
     * @param uri source uri of a file which is to be modified
     * @param fileAsset a FileAsset which has modified filePath information
     * @return modification status. <0> for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    int32_t ModifyAsset(const string &uri, const FileAsset &target);

    /**
     * @brief Delete an existing file
     *
     * @param uri source uri of a file which is to be deleted
     * @return deletion status. <0> for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    int32_t DeleteAsset(const string &uri);

    /**
     * @brief Open an existing file
     *
     * @param uri source uri of a file which is to be opened
     * @param mode Mode in which the file is to be opened. Refer media_data_ability_const.h for
     *             the list of supported file modes
     * @return file descriptor for the opened file. Upon failure, return value will be <= 0
     * @since 1.0
     * @version 1.0
     */
    int32_t OpenAsset(const string &uri, string &mode);

    /**
     * @brief Close an opened file
     *
     * @param uri source uri of a file which is to be closed
     * @param fd file descriptor for the file which is to be closed
     * @return close status. <0> for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    int32_t CloseAsset(const string &uri, const int32_t fd);

    /**
     * @brief Create a new album
     *
     * @param album An AlbumAsset object which has the albumPath information
     * @return An album id if success. Upon failure, returns value < 0
     * @since 1.0
     * @version 1.0
     */
    int32_t CreateAlbum(const AlbumAsset &album);

    /**
     * @brief Modify an existing album
     *
     * @param uri album id for the album which is to be modified
     * @param target an AlbumAsset object which has the new album name information
     * @return modification status. <0> for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    int32_t ModifyAlbum(const int32_t albumId, const AlbumAsset &target);

    /**
     * @brief Delete an existing album
     *
     * @param uri album id of the album which is to be deleted
     * @return deletion status. <0> for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    int32_t DeleteAlbum(const int32_t albumId);

    /**
     * @brief Obtain a FetchResult object from which AlbumAsset File Assets can be obtained
     *
     * @param albumId album id for the album from where the file assets are to be fetched
     * @param fetchOptions Condition for obtaining the list of album file assets
     * @return a FetchResult object which has metadata for a list of files contained in the specified album
     * @since 1.0
     * @version 1.0
     */
    unique_ptr<FetchResult> GetAlbumFileAssets(const int32_t albumId, const MediaFetchOptions &fetchOptions);
    /**
     * @brief Obtain a mediaVolume object from MediaAssets can be obtained
     *
     * @param MediaVolume MediaVolume for outValue
     * @return errorcode
     * @since 1.0
     * @version 1.0
     */
    int32_t QueryTotalSize(MediaVolume &outMediaVolume);

private:
    static shared_ptr<DataShare::DataShareHelper> sAbilityHelper_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LIBRARY_MANAGER_H_
