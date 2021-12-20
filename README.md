# MediaLibrary<a name="EN-US_TOPIC_0000001147574647"></a>

- [Introduction<a name="section1158716411637"></a>](#introduction)
- [Directory Structure<a name="section161941989596"></a>](#directory-structure)
- [Usage Guidelines<a name="usage-guidelines"></a>](#usage-guidelines)
    - [New APIs<a name="new-api"></a>](#new-api)
        - [File operations<a name="file-operation"></a>](#file-operation)
        - [Album operations<a name="album-operation"></a>](#album-operation)
        - [Listener Support<a name="listener-support"></a>](#listener-support)
        - [Query File assets<a name="get-fileasset"></a>](#get-fileasset)
        - [Query Album assets<a name="get-album"></a>](#get-album)
        - [Media Scanner APIs<a name="scan-api"></a>](#scan-api)
    - [Old APIs<a name="old-api"></a>](#old-api)
        - [Query AudioAsset<a name="get-audioasset"></a>](#query-audioasset)
        - [Create Album<a name="create-album"></a>](#create-album)
        - [Copy ImageAsset<a name="copy-imageasset"></a>](#copy-imageasset)
- [Repositories Involved<a name="section1533973044317"></a>](#repositories-involved)


## Introduction<a name="section1158716411637"></a>

The **medialibrary\_standard**  repository provides a set of easy-to-use APIs for getting media file metadata information.
MediaLibrary APIs can only be used internally, not exposed to public application currently.

The various capabilities can be categorized as below:
- Query for audio, video and image files metadata information
- Query for image and video albums
- File operations like create, modify and delete media file
- Album operations like create, rename and delete album


## Directory Structure<a name="section161941989596"></a>

The structure of the repository directory is as follows:
```
/foundation/multimedia/medialibrary_standard    # Medialibrary code
├── frameworks                                  # Framework code
│   ├── innerkitsimpl                           # Internal Native API implementation
│   │   ├── media_library                       # Native MediaLibrary implementation
│   │   ├── medialibrary_data_ability           # Native Medialibrary data ability implementation
│   │   └── media_scanner                       # Native MediaScanner implementation
│   │   └── media_library_manager               # Native Medialibrary Helper APIs
│   │   └── test                                # Unittests for medialibrary, data ability and mediscanner APIs
│   └── kitsimpl
│       └── medialibrary                        # External MediaLibrary and MediaScanner NAPI implementation
├── interfaces                                  # Interfaces
│   ├── innerkits                               # Internal Native APIs
│   └── kits                                    # External JS APIs
├── services                                    # Service implementation
│   ├── media_library_service                   # MediaLibrary service implementation
│   └── media_scanner_service                   # MediaScanner ability service implementation
├── LICENSE                                     # License file
├── ohos.build                                  # Build file
└── sa_profile                                  # Service configuration profile
```

## Usage Guidelines<a name="usage-guidelines"></a>
### New APIs<a name="new-api"></a>

A Medialibrary instance is required to call the new APIs to perform file and album related operations.<br>
Use **getMediaLibrary** API to obtain the **Medialibrary** instance
```
import mediaLibrary from '@ohos.multimedia.medialibrary'
const media = mediaLibrary.getMediaLibrary();
```

#### File operations<a name="file-operation"></a>
We can use APIs like **createAsset**, **modifyAsset**, **openAsset** , **closeAsset** and **deleteAsset** to handle different file operations. The following steps describe how to use the createAsset API to create a new file

1. Create a new FileAsset object and set the path of the file and type of the file to be created
    ```
    let obj = new mediaLibrary.FileAsset;
    obj.path = “/data/media/test_video.mp4”;
    obj.mediaType = mediaLibrary.MediaType.VIDEO;
    ```
2. Use the **createAsset** API to create files. The return value will be a uri, which can be used later to modify, open, close or delete the same file using the File operation APIs.
    ```
    let createUri = media.createAsset(obj, AsyncCallback);
    ```
    NOTE: AsyncCallback and Promise implementation is not explained in the given API calls. API calls are only specified to showcase how the inputs are used with a given API.

The following example shows how to modify an asset using the uri which was obtained from createAsset() API.
1. Create a new FileAsset object which will act as target for Modify. Set the modified path for the file.
    ```
    let obj = new mediaLibrary.FileAsset;
    obj.path = “/data/media/test_video_modified.mp4”;
    ```
2. Use the **modifyAsset** API to modify files. The return will be 0 for success and negative value in case of failure.<br>
'createUri' is a unique identifier which points to the original file which will be modified.
    ```
    media.modifyAsset(createUri, obj, AsyncCallback);
    ```

#### Album operations<a name="album-operation"></a>
We can use APIs like **createNewAlbum**, **modifyAlbum** and **deleteAlbum** to handle different album operations. The following steps describe how to use the createNewAlbum API to create a new album

1. Create a new Album object and set the path of the new album as shown below
    ```
    let obj = new mediaLibrary.Album;
    obj.path = “/data/media/new_folder”;
    ```
2. Use the **createNewAlbum** API to create folder. The return value will be an unique albumId for the given album if create is successful, or negative value in case of failure.<br>
    ```
    let albumId = media.createNewAlbum(obj, AsyncCallback);
    ```

The following example shows how to modify and delete an album which was obtained from createNewAlbum() API. 'albumId' is an unique identifier pointing to the original file which will be input for modify and delete album operation.

1. Use the **modifyAlbum** API to modify the album. Return value will be 0 in case of success and negative value in case of failure. 
    ```
    let obj = new mediaLibrary.Album;
    obj.albumName = “ModifiedAlbum”;
    let ret = media.modifyAlbum(albumId, obj, AsyncCallback);
    ```
2. Use the **deleteAlbum** API to delete the album. Return value will be 0 in case of success and negative value in case of failure.
    ```
    let ret = media.deleteAlbum(albumId, AsyncCallback);
    ```

#### Listener Support <a name="listener-support"></a>
We can use **on** and **off** APIs to register and unregister for notification of events when any modification happens at database for a specified mediatype. The following example shows how to register for such events.

1. Mention the mediatypes for which listener has to be registered.
    ```
    let type = ["image", "video"];
    ```
2. Use the **on** API to register for callbacks when any update occurs for image or video in database.
    ```
    media.on(type, AsyncCallback);
    ```
    When callback is received, the callback arguments will specify the mediatype for which change is observed.

#### Query File assets<a name="get-fileasset"></a>
 - **getFileAssets** to obtain metadata for all files present inside a specific path based on certain conditions. The API returns a result set which clients can use to retrieve information about all the files in the path.
 - **getFirstObject** returns the first file information from the result set.
 - **getNextObject** returns the next file information from the result set.
 - **getPositionObject** returns the file information at the given index in the result set.
 - **getAllObject** returns the list of all files as an array.
 - **getLastObject** returns the last file information.
 - **isAfterLast** returns a boolean value which indicates whether the list is fully traversed.
 - **getCount** returns the number of files present in the path.

 The following example shows how to use **getFileAssets** to query all files within a path.

1. Mention the filter details. The below sql statement will get all image and video assets present in /data/media/dcim recursively and sorted by their file id.
    ```
    let imageType = mediaLibrary.MediaType.IMAGE;
    let videoType = mediaLibrary.MediaType.VIDEO;
    let fileKeyObj = mediaLibrary.FileKey; // Specifies which column in database
    let fetchOp = {
        selections: fileKeyObj.PATH + " LIKE ? AND " + fileKeyObj.MEDIA_TYPE + " IN (?,?)",
        selectionArgs: ["/data/media/dcim/%", imageType.toString(), videoType.toString()],
        order: fileKeyObj.ID + " ASC"
    }; // creates sql's WHERE condition for querying database
    ```
2. Use the **getFileAssets** and **getAllObject** APIs to return all image and video assets in the path mentioned above.
    ```
    media.getFileAssets(fetchOp, (err, data) => {
        if (data != undefined) {
            data.getAllObject((err1, data1) => {
                if (data1 != undefined) {
                    //print info like data1[0].path, data1[0].uri, etc.
                }
            });
        }
    });
    ```

#### Query Album assets<a name="get-album"></a>
 - **getAlbums** to get all the albums present inside a specific path. After getting all album details , getFileAssest API can be used to fetch information about the files present inside the album

 The following example shows how to use **getAlbums** to query all albums within a path and how to use **getFileAssest** to fetch album file information

1. The below sql statement will get all image files present in all the albums inside /data/media/imageAlbums folder
    ```
    let fileKeyObj = mediaLibrary.FileKey;
    let albumFetchOp = {
        selections: fileKeyObj.PATH + “ LIKE ? AND “ + fileKeyObj.RELATIVE_PATH + “ = ?”,
        selectionArgs: [“/data/media/imageAlbums/%”, “/data/media/imageAlbums”]
    };

    let imageType = mediaLibrary.MediaType.IMAGE;
    let fileFetchOp = {
        selections: fileKeyObj.MEDIA_TYPE + “ = ?”,
        selectionArgs: [imageType.toString()]
    };
    ```
2. Use the **getAlbums** and **getFileAssets** APIs to return all image assets in the album mentioned above.
    ```
    media.getAlbums(albumFetchOp, (err, data) => {
        if (data != undefined) {
            let len = data.length;
            for(let i = 0; i < len; i++) {
                data[i].getFileAssets(fileFetchOp, AsyncCallback);
            }
        }
    });
    ```
    Use the output from AsyncCallback in similar manner as in <a href="#get-fileasset">previous section</a>

#### Media Scanner APIs<a name="scan-api"></a>
Media Scanner APIs **scanDir** and **scanFile** can be use to scan a particular folder and file respectively and update their metadata in the database.

 1. Use **getScannerInstance** API to obtain the **MediaScanner** instance
    ```
    const scannerObj = mediaLibrary.getScannerInstance();
    ```
2. Set the path for scanning
    ```
    let filePath = “/data/media/audio/SampleAudio.aac”;
    let folderPath = “/data/media/audio”;
    ```
3. Use the **scanDir** API to scan the folder and **scanFile** API to scan a file. The return value will be an object which has two parameters: status and fileUri.
    ```
    scannerObj.scanFile(filePath, (err, data) => {
        if (data != undefined) {
            // print data.fileUri
            // print data.status
        }
    });
    ```
    scanFile returns status <b>0</b> and the corresponding file uri from the database if scan is successful. Upon failure, it returns an errorcode and empty uri string.

    ```
    scannerObj.scanDir(folderPath, (err, data) => {
        if (data != undefined) {
            // print data.status
        }
    });
    ```
    scanDir returns status <b>0</b> if the scan was successful or else an errorcode is returned. fileUri is not associated with scanDir operation.

### Old APIs<a name="old-api"></a>

#### Query AudioAsset<a name="get-audioasset"></a>
We can use APIs like **GetMediaAssets**, **GetAudioAssets**, **GetVideoAssets** and **GetImageAssets** to query for different file metadata information. The following steps describe how to use the GetAudioAssets API to obtain audio related metadata.
1. Use **GetMediaLibraryClientInstance** API to obtain the **Medialibrary** instance
    ```
    IMediaLibraryClient* mediaLibClientInstance = IMediaLibraryClient::GetMediaLibraryClientInstance();
    ```
2. Set the scanning directory for audio files in **selection** string. The selection value will be a relative path to a media root directory i.e. "/data/media". It will check for audio files recursively in the given directory.
    ```
    string selection = "audios/audio1";
    ```
3. Use the **GetAudioAssets** API to query for audio files. The input argument *selectionArgs* does not have any use case currently. The API returns a list of *AudioAsset*.
    ```
    vector<string> selectionArgs;
    vector<unique_ptr<AudioAsset>> audioAssets = mediaLibClientInstance->GetAudioAssets(selection, selectionArgs);
    ```
4. We can obtain audio metadata for each file from the list.
    ```
    for (size_t i = 0; i < audioAssets.size(); i++) {
        cout << audioAssets[i]->uri_ << endl;
        cout << audioAssets[i]->size_ << endl;
        cout << audioAssets[i]->dateAdded_ << endl;
        cout << audioAssets[i]->dateModified_ << endl;
        cout << audioAssets[i]->albumName_ << endl;
        cout << audioAssets[i]->duration_ << endl;
        cout << audioAssets[i]->artist_ << endl;
    }
    ```

#### Create Album<a name="create-album"></a>
MediaLibrary offers APIs for application to perform album operations like create, modify and delete. Below are the steps on how to create a new album.
1. Use **GetMediaLibraryInstance** API to obtain the **Medialibrary** instance
    ```
    IMediaLibraryClient* mediaLibClientInstance = IMediaLibraryClient::GetMediaLibraryClientInstance();
    ```
2. Specify the album type. It can be either *ASSET_GENERIC_ALBUM*, *ASSET_IMAGEALBUM* or *ASSET_VIDEOALBUM*.
    ```
    AssetType assetType = ASSET_VIDEOALBUM;
    ```
3. Create a new **AlbumAsset** object and provide a new album name. Below album "new_video" will get created in the path "/data/media/videos".
    ```
    AlbumAsset albumAsset;
    albumAsset.albumName_ = "videos/new_video";
    ```
4. Use **CreateMediaAlbumAsset** API to create the new album in the device. The return value will be boolean, which states whether the album creation succeeded or failed.
    ```
    bool errCode = mediaLibClientInstance->CreateMediaAlbumAsset(assetType, albumAsset);
    ```

#### Copy ImageAsset<a name="copy-imageasset"></a>
File operations are supported via APIs like **CreateMediaAsset**, **ModifyMediaAsset**, **CopyMediaAsset**, **DeleteMediaAsset**. The example below explains the usage of CopyMediaAsset API.
1. Use **GetMediaLibraryInstance** API to obtain the **Medialibrary** instance
    ```
    IMediaLibraryClient* mediaLibClientInstance = IMediaLibraryClient::GetMediaLibraryClientInstance();
    ```
2. Specify the asset type. It can be either *ASSET_MEDIA*, *ASSET_IMAGE*, *ASSET_AUDIO* or *ASSET_VIDEO*.
    ```
    AssetType assetType = ASSET_IMAGE;
    ```
3. Define the source and target **ImageAsset**. The target asset must specify the new album name where the source asset will be copied.
    ```
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;

    srcMediaAsset.name_ = "image1.jpg";
    srcMediaAsset.uri_ = "/data/media/images/001/image1.jpg";

    dstMediaAsset.albumName_ = "images/new_image";
    ```
4. Use **CopyMediaAsset** API to copy the source asset to target asset's album name location. The boolean return value denotes the status of the file operation. The source file "image1.jpg" will get copied to "/data/media/images/new_image".
    ```
    bool errCode = mediaLibClientInstance->CopyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    ```

Please refer [**imedia_library_client.h**](https://gitee.com/openharmony/multimedia_medialibrary_standard/blob/master/interfaces/innerkits/native/include/imedia_library_client.h) for more APIs.


## Repositories Involved<a name="section1533973044317"></a>
[multimedia/medialibrary_standard](https://gitee.com/openharmony/multimedia_medialibrary_standard)
