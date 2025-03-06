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

import { Context, MediaChangeRequest } from "./media_library_common.ets";
import { PhotoAssetHandle } from "./photo_asset.ets";
import { AlbumHandle } from "./photo_album.ets";

export class BusinessError<T = void> {
    code: number = 0;
    data?: T;
}

export type AsyncCallback<T, E = void> = (err: BusinessError<E>, data?: T) => void;

class MediaAlbumChangeRequestHandle implements MediaChangeRequest {
    static { loadLibrary("ani_photo_access_helper"); }
    private  nativeHandle: long = 0;

    constructor(context: long) {
        if(this.nativeHandle == 0){
            this.nativeHandle = context;
        }
    }

    native static create(album: AlbumHandle): MediaAlbumChangeRequestHandle;
    native placeBefore(album: AlbumHandle): void;
    native mergeAlbum(album: AlbumHandle): void;
    native dismissAssets(assets: Array<PhotoAssetHandle>): void;
    native addAssets(assets: Array<PhotoAssetHandle>): void;
    native moveAssets(assets: Array<PhotoAssetHandle>, targetAlbum: AlbumHandle): void;
    native setAlbumName(name: string):void;
    native setCoverUri(coverUri: string): void;
    native recoverAssets(assets: Array<PhotoAssetHandle>): void;
    native setDisplayLevel(displayLevel: int): void;
    native setIsMe(): void;
    native deleteAssets(assets: Array<PhotoAssetHandle>): void;
    native static deleteAlbums(context: Context, assets: Array<AlbumHandle>): void;
}