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

#include "medialibrary_smartalbum_map_operations.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t InsertAlbumInfoUtil(const ValuesBucket &valuesBucket,
                            shared_ptr<RdbStore> rdbStore,
                            const MediaLibrarySmartAlbumMapDb &smartAlbumMapDbOprn)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    return const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapDbOprn).
    InsertSmartAlbumMapInfo(values, rdbStore);
}
int32_t MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperations(const string &oprn,
                                                                           const ValuesBucket &valuesBucket,
                                                                           const shared_ptr<RdbStore> &rdbStore)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    int32_t errCode = DATA_ABILITY_FAIL;
    ValueObject valueObject;

    if (oprn == MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM) {
        errCode = InsertAlbumInfoUtil(values, rdbStore, smartAlbumMapDbOprn);
    }
    return errCode;
}
} // namespace Media
} // namespace OHOS