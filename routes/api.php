<?php

use App\Http\Controllers\ActivationCodeController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\CategoryController;
use App\Http\Controllers\ChapterController;
use App\Http\Controllers\ChoiceController;
use App\Http\Controllers\CourseController;
use App\Http\Controllers\CourseValueController;
use App\Http\Controllers\ExportableFileController;
use App\Http\Controllers\LesionController;
use App\Http\Controllers\NewsController;
use App\Http\Controllers\NotificationController;
use App\Http\Controllers\QuestionController;
use App\Http\Controllers\QuizController;
use App\Http\Controllers\StatisticsController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\UserWatchController;
use App\Http\Controllers\VideoController;
use Illuminate\Support\Facades\Route;

Route::middleware(['language'])->group(function (){
    Route::prefix('/v1/auth/')->group(function (){
        Route::post('/register' , [AuthController::class , 'signup']);
        Route::post('/login' , [AuthController::class , 'login']);
        Route::post('/admin/login' , [AuthController::class , 'loginAdmin']);
    });
    /* @commented code for routes if the mobile can discover content without auth */
//    Route::prefix('/news')->group(function (){
//        Route::get('/visible' , [NewsController::class , 'visibleNews']);
//    });
//    Route::prefix('/categories')->group(function (){
//        Route::get('/visible' , [CategoryController::class , 'visibleCategories']);
//    });
//    Route::prefix('/courses')->group(function () {
//        Route::get('/visible/{category}', [CourseController::class, 'getVisibleCourses']);
//        Route::get('/show/{course}' , [CourseController::class , 'showCourseWithInfo']);
//    });


    Route::middleware(['auth:sanctum'])->group(function () {
//    Admin Routes
        Route::prefix('/v1')->group(function (){
            Route::middleware(['admin'])->group(function (){
                Route::get('/videos/get' , [VideoController::class , 'getVideos']);
                Route::prefix('/files')->group(function (){
                    Route::get('/pdf_lesion/{path}' , [LesionController::class , 'getPdfLesion'])->where('path', '.*');
                    Route::get('/all', [ExportableFileController::class, 'getAllFiles']);
                    Route::get('/download/{fileName}', [ExportableFileController::class, 'downloadFile']);
                    Route::delete('/delete/{fileName}', [ExportableFileController::class, 'deleteFile']);
                });
                Route::prefix('/news')->group(function (){
                    Route::get('/all' , [NewsController::class , 'index']);
                    Route::post('/create' , [NewsController::class , 'store']);
                    Route::get('/show/{news}' , [NewsController::class , 'show']);
                    Route::post('/update/{news}' , [NewsController::class , 'update']);
                    Route::delete('/delete/{news}' , [NewsController::class , 'destroy']);
                    Route::patch('/switchVisibility/{news}' , [NewsController::class , 'switchVisibility']);
                });
                Route::prefix('/categories')->group(function (){ //done
                    Route::get('/all' , [CategoryController::class , 'gelAllCategories']);
                    Route::get('/show/{category}' , [CategoryController::class , 'show']);
                    Route::post('/create' , [CategoryController::class , 'store']);
                    Route::patch('/update/{category}' , [CategoryController::class , 'updateCategory']);
                    Route::patch('/switch-visibility/{category}' , [CategoryController::class , 'switchVisibility']);
                    Route::delete('/delete/{category}' , [CategoryController::class , 'destroy']);
                });
                Route::prefix('/chapters')->group(function (){
                    Route::get('/all/{course}' , [ChapterController::class , 'getAll']); //unused
                    Route::patch('/switchVisibility/{chapter}' , [ChapterController::class , 'switchVisibility']); // unused
                    Route::post('/create' , [ChapterController::class , 'store']); //done
                    Route::patch('/update/{chapter}' , [ChapterController::class , 'update']); //done
                    Route::delete('/delete/{chapter}' , [ChapterController::class , 'destroy']); //done
                });
                Route::prefix('/lesions')->group(function (){
                    Route::get('/all/{chapter}' , [LesionController::class , 'getAll']); //not used any more
                    Route::patch('/switchVisibility/{lesion}' , [LesionController::class , 'switchVisibility']); //not used
                    Route::post('/create' , [LesionController::class , 'store']); // done
                    Route::post('/update/{lesion}' , [LesionController::class , 'update']); //done
                    Route::delete('/delete/{lesion}' , [LesionController::class , 'delete']); //done
                });
                Route::prefix('/statistics')->group(function (){
                    Route::get('/get' , [StatisticsController::class , 'statistics']); //done
                    Route::get('/basicStatistics' , [StatisticsController::class , 'basicStatistics']); //done
                    Route::get('/basicStatistics' , [StatisticsController::class , 'basicStatistics']); //done
                    Route::get('/last-enrolled' , [StatisticsController::class , 'getLastEnrolled']); //done
                    Route::post('/reset' , [StatisticsController::class , 'reset']); //done
                });
                Route::prefix('/activationCodes')->group(function (){
                    Route::post('/generate' , [ActivationCodeController::class , 'store']);
                    Route::post('/checkCode' , [ActivationCodeController::class , 'checkCode']);
                    Route::get('/unexpired' , [ActivationCodeController::class , 'getUnExpiredCodes']);
                });
//                vide
                Route::prefix('/users')->group(function (){
                    Route::patch('/switchBlockAccount/{user}' , [UserController::class , 'switchBlockState']); //done
                    Route::get('/profileOf/{user}' , [UserController::class , 'getUserProfile']);
                    Route::post('/create' , [UserController::class , 'create']); // done
                    Route::get('/students' , [UserController::class , 'getStudents']); // done
                    Route::get('/all' , [UserController::class , 'getAllUser']); // done
                    Route::get('/spicialAccounts' , [UserController::class , 'getSpicialAccounts']); //done
                    Route::get('/blocked' , [UserController::class , 'getAllBlockedUser']);
                    Route::get('/teachers' , [UserController::class , 'getTeacher']); //done
                    Route::get('/insideCourse/{course}' , [UserController::class , 'getAllUserThatSignInToThis']);//done
                    Route::get('/allCoursesOf/{user}' , [UserController::class , 'GetAllInrolnmentCourseForThis']); //done
                     //done
                    Route::patch('/resetPassword/{user}' , [UserController::class , 'resetPassword']);
                });

                Route::prefix('/courses')->group(function (){
                    Route::post('/create' , [CourseController::class , 'store']); //done
                    Route::get('/all' , [CourseController::class , 'getAllCourses']); //done
                    Route::get('/visible' , [CourseController::class , 'visibleCourses']); //used in api | done
                    Route::post('/update/{course}' , [CourseController::class , 'update']); //done
                    Route::patch('/switchOpenStatus/{course}' , [CourseController::class  , 'switchOpenStatus']); //done
                    Route::patch('/switchVisibility/{course}' , [CourseController::class , 'switchVisibility']); //done
                    Route::get('/getEnrollmentWithTypeOfCodes' , [CourseController::class , 'getEnrollmentWithTypeOfCodes']);
                    Route::post('/addUser/{user}/toCourse/{course}' , [CourseController::class , 'manualInrolStudentInCourse']); //done
                    Route::delete('/cancelInrolment/{inrollment}' , [CourseController::class , 'cancelInfolement']); //done
                    Route::delete('/delete/{course}' , [CourseController::class , 'destroy']); //done
                    Route::get('/allInrolments' , [CourseController::class , 'getAllIneolments']);
                    Route::post('/add-value/{course}' , [CourseValueController::class , 'store']);//done
                    Route::delete('/delete-value/{value}' , [CourseValueController::class , 'destroy']);//done
                    Route::patch('/update-value/{value}' , [CourseValueController::class , 'update']);//done
                });

                Route::prefix('/notifications')->group(function (){
                    Route::post('/push' , [NotificationController::class , 'sendNotificationForAllUser']);
                });

                Route::prefix('/questions')->group(function () {
                    Route::get('/all' , [QuestionController::class , 'getAll']); //done
                    Route::get('/show/{question}' , [QuestionController::class , 'show']); //done
                    Route::post('/create' ,[QuestionController::class , 'store']); // done
                    Route::post('/update/{question}' , [QuestionController::class , 'update']);
                    Route::post('/newChoice/{question}' , [ChoiceController::class , 'store']);//done
                    Route::prefix('/choices')->group(function (){
                       Route::post('/update/{choice}' , [ChoiceController::class , 'updateChoice']);
                       Route::delete('/delete/{choice}' , [ChoiceController::class , 'destroy']);//done
                       Route::patch('/switch-to-true/{choice}' , [ChoiceController::class , 'makeChoiceTrue']);//done
                       Route::patch('/switch-visibility/{choice}' , [ChoiceController::class , 'switchVisibility']);//done
                    });
                    Route::delete('/delete/{question}' , [QuestionController::class , 'destroy']); //done
                });
                Route::prefix('/quizzes')->group(function (){
                    Route::get('/getAll' , [QuizController::class , 'getAll']); //done
                    Route::post('/create' , [QuizController::class , 'store']); //done
                    Route::get('/show/{quiz}' , [QuizController::class , 'show']); //done
                    Route::patch('/update/{quiz}' , [QuizController::class , 'update']);//done
                    Route::delete('/delete/{quiz}' , [QuizController::class , 'destroy']);//done
                    Route::post('/addQuizToChapter' , [QuizController::class , 'addQuizToChapter']); //done
                    Route::patch('/updateQuizInChapter/{quizChapter}' , [QuizController::class , 'updateQuizInChapter']);
                    Route::delete('/removeFromCourse/{chapterQuiz}' , [QuizController::class , 'removeFromCourse']);
                    Route::prefix('/questions')->group(function (){
                       Route::post('/add' , [QuizController::class , 'addQuestionToQuiz']);//done
                       Route::delete('/delete' , [QuizController::class , 'deleteQuestionFromQuiz']); //done
                       Route::patch('/hide' , [QuizController::class , 'hideVisibility']); //done
                       Route::patch('/show' , [QuizController::class , 'showVisibility']); //done
                    });
                });
            });
//        Mobile App
            Route::middleware(['student_teacher_admin'])->group(function (){
                Route::middleware(['blocked_account'])->group(function (){
                    Route::prefix('/auth')->group(function (){
                        Route::post('/logout' , [AuthController::class , 'logout']);
                    });
                    Route::get('/watch' , [VideoController::class , 'watch']);
                    Route::get('/download' , [VideoController::class , 'download']);
                    Route::prefix('/users')->group(function (){
                        Route::post('/updateProfile/{user}' , [UserController::class , 'updateProfile']);
                        Route::delete('/delete/{user}' , [UserController::class , 'destroy']);
                        Route::get('/myProfile' , [UserController::class , 'profile']);
                        Route::get('/{user}/courses' , [UserController::class , 'inrollnmentCourseOfUser']);
                    });
                    Route::prefix('/news')->group(function (){
                        Route::get('/visible' , [NewsController::class , 'visibleNews']);
                    });
                    Route::prefix('/categories')->group(function (){
                        Route::get('/visible' , [CategoryController::class , 'visibleCategories']);
                    });
                    Route::prefix('/lesions')->group(function (){
                        Route::post('/watch/{lesion}' , [UserWatchController::class , 'makeNewWatch']);
                    });
                    Route::prefix('/courses')->group(function (){
                        Route::get('/visible/{category}', [CourseController::class, 'getVisibleCourses']);
                        Route::get('/search' , [CourseController::class , 'search']);
                        Route::get('/show/{course}' , [CourseController::class , 'showCourseWithInfo']);
                        Route::post('/signIn/{course}' , [CourseController::class , 'inrollInCourse']);
                    });
                });
            });
        });
    });
});
