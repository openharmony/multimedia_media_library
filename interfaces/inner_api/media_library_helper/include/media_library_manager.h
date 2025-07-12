/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#define USERID "100"

#include "datashare_helper.h"
#include "media_volume.h"
#include "pixel_map.h"
#include "unique_fd.h"
#include "media_photo_asset_proxy.h"
#include "media_library_extend_manager.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::DataShare;
#define EXPORT __attribute__ ((visibility ("default")))
struct UriParams;

class MediaLibraryManager {
public:
    EXPORT MediaLibraryManager() = default;
    EXPORT virtual ~MediaLibraryManager() = default;

    /**
     * @brief Returns the Media Library Manager Instance
     *
     * @return Returns the Media Library Manager Instance
     * @since 1.0
     * @version 1.0
     */
    EXPORT static MediaLibraryManager *GetMediaLibraryManager();

    /**
     * @brief Initializes the environment for Media Library Manager
     *
     * @param context The Ability context required for calling Data Ability Helper APIs
     * @since 1.0
     * @version 1.0
     */
    EXPORT void InitMediaLibraryManager(const sptr<IRemoteObject> &token);

    /**
     * @brief Initializes the environment for Media Library Manager
     *
     * @since 1.0
     * @version 1.0
     */
    EXPORT void InitMediaLibraryManager();

    /**
     * @brief Close an opened file
     *
     * @param uri source uri of a file which is to be closed
     * @param fd file descriptor for the file which is to be closed
     * @return close status. <0> for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    EXPORT int32_t CloseAsset(const string &uri, const int32_t fd);

    /**
     * @brief create an photo or video asset
     *
     * @param displayName file displayName
     * @return asset uri for success and <""> for fail
     * @since 1.0
     * @version 1.0
     */
    EXPORT string CreateAsset(const string &displayName);

    /**
     * @brief open photo or video
     *
     * @param uri uri of the asset
     * @param openMode openMode "rw", "w", "r"
     * @return fileDescriptor for success and <-1> for fail
     * @since 1.0
     * @version 1.0
     */
    EXPORT int32_t OpenAsset(string &uri, const string openMode);

    /**
     * @brief Obtain a mediaVolume object from MediaAssets can be obtained
     *
     * @param MediaVolume MediaVolume for outValue
     * @return errorcode
     * @since 1.0
     * @version 1.0
     */
    EXPORT int32_t QueryTotalSize(MediaVolume &outMediaVolume);

    /**
     * @brief Query new uri by old uri
     *
     * @param uris old uris
     * @return map of old uris to new uris
     * @since 1.0
     * @version 1.0
     */
    EXPORT std::unordered_map<std::string, std::string> GetUrisByOldUris(std::vector<std::string> uris);

    /**
     * @brief Make a query from database
     *
     * @param columnName a column name in datebase
     * @param value a parameter for input which is a uri or path
     * @param columns query conditions
     * @return query result
     * @since 1.0
     * @version 1.0
     */
    EXPORT static std::shared_ptr<DataShareResultSet> GetResultSetFromDb(string columnName, const string &value,
        vector<string> &columns);

    /**
     * @brief get file path from uri
     *
     * @param fileUri a parameter for input  which is uri
     * @param filePath a parameter for output  which is path
     * @param userId  a parameter for user id
     * @return errorcode
     * @since 1.0
     * @version 1.0
     */
    EXPORT int32_t GetFilePathFromUri(const Uri &fileUri, std::string &filePath, string userId = USERID);

    /**
     * @brief Obtain a mediaVolume object from MediaAssets can be obtained
     *
     * @param fileUri a parameter for output  which is uri
     * @param filePath a parameter for input  which is path
     * @param userId  a parameter for user id
     * @return errorcode
     * @since 1.0
     * @version 1.0
     */
    EXPORT int32_t GetUriFromFilePath(const std::string &filePath, Uri &fileUri, string &userId);

    EXPORT std::unique_ptr<PixelMap> GetThumbnail(const Uri &uri);

    /**
     * @brief Obtain a batch of astc data
     *
     * @param uriBatch parameter for input, indicates the range of astc data that needs to be obtained
     * @param astcBatch parameter for output
     * @return if obtain success, return 0; Otherwise return error code.
     */
    EXPORT int32_t GetBatchAstcs(
        const std::vector<std::string> &uriBatch, std::vector<std::vector<uint8_t>> &astcBatch);

    /**
     * @brief Obtain pixelmap of astc
     *
     * @param uri a parameter for input which is uri
     * @return if obtain success, return PixelMap; Otherwise return nullptr
     */
    EXPORT std::unique_ptr<PixelMap> GetAstc(const Uri &uri);

    /**
     * @brief Open video of moving photo to read
     *
     * @param uri asset uri of the moving photo
     * @return read fd for success and <-1> for fail
     */
    EXPORT int32_t ReadMovingPhotoVideo(const string &uri);

    /**
     * @brief Open video of moving photo to read, support cloud file
     *
     * @param uri asset uri of the moving photo
     * @param offset offset of the video in fd
     * @return read fd for success and <-1> for fail
     */
    EXPORT int32_t ReadMovingPhotoVideo(const string &uri, off_t &offset);

    /**
     * @brief Open private moving photo to read
     *
     * @param uri asset uri of the moving photo
     * @return read fd for success and <-1> for fail
     */
    EXPORT int32_t ReadPrivateMovingPhoto(const string &uri);

    /**
     * @brief Get image uri of moving photo
     *
     * @param uri asset uri of the moving photo
     * @return image uri
     */
    EXPORT std::string GetMovingPhotoImageUri(const string &uri);

    /**
     * @brief Get date modified of moving photo
     *
     * @param uri asset uri of the moving photo
     * @return if obtain success, return date_modified; Otherwise return -1
     */
    EXPORT int64_t GetMovingPhotoDateModified(const string &uri);

    /**
     * @brief Create PhotoAssetProxy
     *
     * @param cameraShotType a parameter for input, indicates camera shot type
     * @param callingUid a parameter for input, indicates calling uid
     * @param userId a parameter for input, indicates user id
     * @return if obtain success, return PhotoAssetProxy; Otherwise return nullptr
     */
    EXPORT std::shared_ptr<PhotoAssetProxy> CreatePhotoAssetProxy(CameraShotType cameraShotType, uint32_t callingUid,
        int32_t userId, uint32_t callingTokenId = 0);
    EXPORT static std::string GetSandboxPath(const std::string &path, const Size &size, bool isAstc);
    EXPORT static void GetUriIdPrefix(std::string &fileUri);
    EXPORT static bool IfSizeEqualsRatio(const Size &imageSize, const Size &targetSize);
    EXPORT static int32_t OpenReadOnlyAppSandboxVideo(const string& uri);
    EXPORT static int64_t GetSandboxMovingPhotoTime(const string& uri);
    EXPORT int32_t GetAstcYearAndMonth(const std::vector<string> &uris);

    sptr<IRemoteObject> InitToken();
    int32_t CheckResultSet(std::shared_ptr<DataShareResultSet> &resultSet);

private:
    int32_t ReadMovingPhotoVideo(const string &uri, const string &option);
    static int OpenThumbnail(std::string &uriStr, const std::string &path, const Size &size, bool isAstc);
    static unique_ptr<PixelMap> QueryThumbnail(UriParams& params);
    static unique_ptr<PixelMap> DecodeThumbnail(UniqueFd& uniqueFd, const Size& size, DecodeDynamicRange dynamicRange);
    static unique_ptr<PixelMap> GetPixelMapWithoutDecode(UniqueFd &uniqueFd, const Size& size);
    static unique_ptr<PixelMap> DecodeAstc(UniqueFd &uniqueFd);

    static shared_ptr<DataShare::DataShareHelper> sDataShareHelper_;
    static sptr<IRemoteObject> token_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LIBRARY_MANAGER_H_
