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

#ifndef OHOS_MEDIALIBRARY_FILE_MANAGER_H
#define OHOS_MEDIALIBRARY_FILE_MANAGER_H

#include <string>
#include <vector>

#include "data_ability_predicates.h"
#include "hilog/log.h"
#include "imedia_scanner_client.h"
#include "media_data_ability_const.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_unistore_manager.h"
#include "native_album_asset.h"
#include "uri.h"
#include "value_object.h"
#include "values_bucket.h"

#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "rdb_utils.h"
#include "result_set_bridge.h"

namespace OHOS {
namespace Media {

class MediaLibraryFileManager {
public:
    MediaLibraryFileManager();
    virtual ~MediaLibraryFileManager(){};

    virtual int32_t CreateFile(MediaLibraryCommand &cmd);
    virtual int32_t BatchCreateFile(MediaLibraryCommand &cmd);
    virtual int32_t DeleteFile(MediaLibraryCommand &cmd);
    virtual int32_t RenameFile(MediaLibraryCommand &cmd);
    virtual int32_t ModifyFile(MediaLibraryCommand &cmd);
    virtual std::shared_ptr<DataShare::ResultSetBridge> LookupFile(MediaLibraryCommand &cmd,
                                                                   const std::vector<std::string> &columns);

    virtual int32_t OpenFile(MediaLibraryCommand &cmd, const std::string &mode);
    virtual int32_t CloseFile(MediaLibraryCommand &cmd);
    virtual int32_t IsDictionary(MediaLibraryCommand &cmd);
    virtual int32_t GetCapatity(MediaLibraryCommand &cmd);

protected:

    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFiles(MediaLibraryCommand &cmd);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFavFiles(MediaLibraryCommand &cmd);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryTrashFiles(MediaLibraryCommand &cmd);

    // void CreateThumbnail(const shared_ptr<MediaLibraryThumbnail> &mediaThumbnail,
    // string id);
    shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &uriStr);

    std::shared_ptr<MediaLibraryUnistore> uniStore_;
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_FILE_MANAGER_H