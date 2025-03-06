/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import { AlbumHandle } from "../ets/photo_album.ets"
import { FetchOptions, FetchOptionsInner } from "./ets/media_library_common.ets";
import { dataSharePredicates } from "@ohos.data.dataSharePredicates";

function main() {
    loadLibrary("photo_access_helper_ani");

    let albumHandle: AlbumHandle = AlbumHandle.create();
    let options: FetchOptionsInner = new FetchOptionsInner;
    options.fetchColumns = new Array<string>("lzh","xfq");
    options.predicates = dataSharePredicates.DataSharePredicates.create();
    albumHandle.getAssetsInner(options);
}