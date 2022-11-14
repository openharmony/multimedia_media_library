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

#include "album_asset.h"
#include "file_asset.h"
#include "fetch_result.h"
#include "media_volume.h"
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
    void InitMediaLibraryManager(const sptr<IRemoteObject> &token);

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
     * @brief Obtain a mediaVolume object from MediaAssets can be obtained
     *
     * @param MediaVolume MediaVolume for outValue
     * @return errorcode
     * @since 1.0
     * @version 1.0
     */
    int32_t QueryTotalSize(MediaVolume &outMediaVolume);

private:
    static shared_ptr<DataShare::DataShareHelper> sDataShareHelper_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LIBRARY_MANAGER_H_
