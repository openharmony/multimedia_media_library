/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


#ifndef MEDIALIBRARY_TRIGGER_TEST_UTILS
#define MEDIALIBRARY_TRIGGER_TEST_UTILS

#include "medialibrary_rdbstore.h"
#include "album_change_info.h"

namespace OHOS {
namespace Media {
const std::string ALBUM_PLUGIN_TABLE = "album_plugin";
class MediaLibraryTriggerTestUtils {
public:
    static void SetRdbStore(std::shared_ptr<MediaLibraryRdbStore> g_rdbStore);
    static void SetTables();
    static void ClearTables();
    static void PrepareData();
    static void RemoveData();
    template<typename T>
    static bool HaveCommonData(std::vector<T> a, std::vector<T> b)
    {
        if (a.size() != b.size()) return false;
        std::sort(a.begin(), a.end());
        std::sort(b.begin(), b.end());
        return a == b;
    }
public:
    static const AccurateRefresh::AlbumChangeInfo SOURCE_ALBUM_INFO;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_TRIGGER_TEST_UTILS