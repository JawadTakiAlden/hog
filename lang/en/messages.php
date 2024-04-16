<?php
return [
    "error" => [
        "server_error" => "Oops! It seems like our server encountered an unexpected error. We're sorry for the inconvenience this may have caused you. Our team has been notified and is working diligently to fix it. In the meantime, you can try refreshing the page or coming back later. Thank you for your patience and understanding",
        "not_found" => "404 Lost in the Digital Wilderness 🌲🔍 Oops! The path you're seeking seems to have vanished into the digital ether. Perhaps it's time to retrace your steps or explore a new route? If you need guidance, our digital rangers are here to help you navigate back to civilization. 🗺️",
        "activation_code_not_found" => "⚠️ Activation Failed! ⚠️
The activation code you provided for the course is not found. Please double-check the code and try again. If you continue to experience issues, please contact support for assistance.",
        "shared_activation_code_already_used_for_this_course" => "⚠️ Activation Failed! ⚠️
The shared activation code you used has already been utilized to activate courses, including this one. Each shared code can only be used once per course. If you have any questions or require assistance, please don't hesitate to reach out to us.",
        "activation_code_expired" => "⚠️ Activation Failed! ⚠️
The activation code you provided for the course has expired. Please obtain a new activation code and try again. If you have any questions or need further assistance, please contact support.",
        "admin_permission" => "Sorry, you do not have sufficient permissions to access requested resource",
        "blocked_account" => "🚫 Uh-oh! It seems we've hit a temporary roadblock. 🛑 Don't worry though, every blockade has a solution! Please reach out to our admin team to iron out this hiccup and get back on track. Your patience is appreciated! 🌟",
        "unknown_lesion_type" => "⚠️ Error: Invalid lesson type! ⚠️ The lesson could not be created because the provided file type is not supported. Accepted file types are PDF and video. Please upload a valid file and try again. Thank you!"
    ],
    "activation_code_controller" => [
        "error" => [
            "select_more_than_one_course" => "Please select only one course for single code type or switch to shared type",
            "select_less_than_two_course" => "Please select more than one course for shared code type or switch to single type.",
        ],
        "generate_codes_successfully" => "Activation codes generated successfully",
    ],
    "auth_controller" => [
        "error" => [
            "credentials_error" => "Oh no! 🙈 It seems like your passcode is playing hide and seek with our servers. Let's coax it out together. 🕵️‍♂️",
            "block_account_while_login" => "🚫 Uh-oh! Looks like you've logged in from a different device. For your security, we've temporarily blocked access."
        ],
        "device_id_unique" => "you're already have an account on this mobile , if you forget your account , call the admin to get it back",
        'register' => "Hooray! You're now part of the family. Let's make some magic happen!",
        "login" => "Welcome :user_name Back for more? Excellent choice! Let's make today even better than yesterday.",
        "logout" => "It's been a pleasure having you here. Take care and come back soon for more.",
    ],
    "category_controller" => [
        "create_category" => "🎉 New category created! 📦 Let's organize our content!",
        "update_category" => "🔄 Category updated! 🚀 Keeping things fresh and organized!",
        "delete_category" => "🗑️ Category deleted! 🚫 Spring cleaning in progress! "
    ],
    "chapter_controller" => [
        "create" => "📚 New chapter added! 🌟 Let's expand our story universe! ",
        "update" => "🔄 Chapter updated! 🔍 Enhancing our narrative journey! ",
        "delete" => "🗑️ Chapter deleted! 🚫 Keeping our story streamlined and focused! ",
        "visibility_switch" => "👁️‍🗨️ Chapter visibility switched! 🌈 Shining the spotlight on our latest narrative twists! "
    ],

    "choice_controller" => [
        "create" => "🎲 New choice added! 🌟 Expanding our options for exploration!",
        "update" => "🔄 Choice updated! 🔍 Fine-tuning our decision-making journey! ",
        "delete" => "🗑️ Choice deleted! 🚫 Keeping our options concise and relevant! ",
        "visibility_switch" => "👁️‍🗨️ Choice visibility switched! 🌈 Shining the spotlight on our selected paths!",
        "make_choice_true" => "✅ Choice confirmed! 🎉 Embracing the chosen path with certainty!"
    ],

    "course_controller" => [
        "error" => [
          "invisible_course" => "🔍 Course visibility update! 📚 The course you're trying to access is currently invisible. If you believe this is a mistake or have any questions, please reach out to the administrator for further assistance.",
          "user_already_enrolled" => "⚠️ Enrollment Failed! ⚠️
You are already enrolled in the course :course_name Duplicate enrollments are not allowed. If you have any questions or concerns, please contact support for assistance.",
          "already_enrolled" => "🛑 Duplicate enrollment detected! 📚 The user :username is already enrolled in :course_name. Please review enrollment records to avoid duplications. ",
          "one_category_at_least" => "⚠️ Error: Course creation failed! ⚠️ To proceed, please provide at least one category for the new course. Categories are essential for organizing our educational content. Please try again with the necessary information. Thank you! ",
          "one_teacher_at_least" => "⚠️ Error: Course creation failed! ⚠️ To proceed, please assign at least one teacher to the new course. Teachers are essential for guiding our students' learning journeys. Please try again with the necessary information. Thank you! ",
          "wrong_match_course_with_code" => "⚠️ Activation Failed! ⚠️
The activation code you provided cannot be used to activate the requested course. Please ensure you have entered the correct code or contact support for assistance. Thank you for your understanding.",
        ],
        "create" => "📚 New course created! 🚀 The course :course_name has been successfully created. It's time to shape minds and inspire learning! ",
        "update" => "🔄 Course updated! 📚 The course :course_name has been successfully updated with the latest information. Let's keep enriching minds and empowering learners! ",
        "delete" => "🧹 Course erased! 📝 Making space for fresh educational endeavors. ",
        "cancel_enrolment" => "🚫 Enrollment canceled Successfully",
        "visibility_switch" => "👁️‍🗨️ Course visibility switched! 🌟 The visibility has been updated. Let's continue shaping our educational landscape! ",
        "free_switch" => "💰 Free status updated! 💸 the course is now :status . We're committed to providing accessible education. ",
        "manual_enrolled_successfully" => "✅ Enrollment process completed successfully! 📚 :username has been successfully enrolled in :course_name. The course roster has been updated.",
        "enroll_successfully" => "✅ Enrollment Successful! 📚
Congratulations! You have been successfully enrolled in the course :course_name Get ready to embark on a journey of learning and discovery. If you have any questions or need assistance, feel free to reach out. Happy learning!"
    ],

    "course_value_controller" => [
        "create" => "🌟 New value added! 💡 Embracing a new principle in our learning journey: :value_name . Let's cultivate a culture of :value_name.",
        "update" => "🔄 Value updated! 🔧 Evolving our understanding of :value_name . Let's continue to refine our commitment to :value_name .",
        "delete" => "🗑️ Value deleted! 🚫 Bid farewell to :value_name. As we let go, we make room for new insights and growth.",
    ],
    "exportable_file_controller" => [
        "delete" => "🗑️ File deleted! 🚫 The file :file_name has been successfully removed from the server. Keeping our storage clean and organized. ",
    ],

    "lesion_controller" => [
        'visibility_switch' => "👁️‍🗨️ Lesson visibility switched! 🌟 The visibility has been updated. Let's continue guiding our learners with clarity and purpose! ",
        "delete" => "🗑️ Lesson deleted! 🚫 A lesson has been successfully removed from the course. Keeping our curriculum streamlined and focused. ",
        "create" => "📝 New lesson created! 🚀 A new lesson has been added to the course. Let's dive into exciting new topics and expand our knowledge! ",
        "update" => "🔄 Lesson updated! 📝 The lesson has been successfully updated with the latest changes. Let's ensure our content remains engaging and informative! ",
    ],

    "news_controller" => [
        "create" => "📰 New news item added to the slider! 🌟 Stay updated with the latest happenings. ",
        "update" => "🔄 News item in the slider updated! 📝 Keeping our audience informed with fresh content. ",
        "delete" => "🗑️ News item removed from the slider! 🚫 Making space for new updates. ",
        "visibility_switch" => "👁️‍🗨️ News item visibility in the slider switched! 🌈 Shining the spotlight on important "
    ],

    "notification_controller" => [
        "send_successfully" => "✉️ Notification sent successfully! 🚀 Your message has been successfully delivered to the intended recipients. Keep the communication flowing! ",
    ],
    "question_controller" => [
        "create" => "📝 New question created! 🌟 Let's expand our knowledge base with insightful inquiries. ",
        "update" => "🔄 Question updated! 🔍 Keeping our questions relevant and engaging. ",
        "delete" => "🗑️ Question deleted! 🚫 Clearing the way for fresh inquiries. ",
    ],
    "quiz_controller" => [
        "error" => [
            "quiz_added_before_to_chapter" => "⚠️ Quiz already added to chapter! ⚠️ The quiz you're attempting to add is already present in this chapter. Please ensure content consistency and avoid duplication. If you have any questions, feel free to reach out. ",
        ],
        "create" => "📝 New quiz created! 🌟 Let the fun and learning begin with this exciting quiz. Get ready to challenge and engage your audience! ",
        "update_quiz_in_chapter" => "🔄 Quiz in chapter updated! 📝 The quiz content has been refreshed to enhance learning experiences within the chapter. Let's keep our learners engaged and motivated! ",
        "update" => "🔄 Quiz updated! 📝 The quiz has been updated with new questions and improvements. Get ready for an enhanced learning experience! ",
        "delete" => "🗑️ Quiz deleted! 🚫 The quiz has been removed. Clearing space for new challenges and learning opportunities. ",
        "delete_from_chapter" => "🗑️ Quiz deleted from chapter! 🚫 The quiz has been removed from this chapter. Adjusting content to better suit our learning objectives. ",
        "questions_added" => "✅ Questions successfully added to the quiz! 🌟 The selected questions have been successfully integrated into the requested quiz. The quiz is now enriched with new content. ",
        "delete_question_from_quiz" => "🗑️ Question deleted from quiz! 🚫 The question has been removed from the quiz. Ensuring the quiz content aligns perfectly with our learning objectives. ",
        "visibility_update" => "👁️‍🗨️ Question visibility updated in the quiz! 🌟 The visibility of questions inside the quiz has been adjusted. Let's ensure a seamless learning experience for our participants! ",
        "quiz_to_chapter_successfully" => "✅ Quiz successfully added to chapter! 📝 The quiz has been successfully integrated into the chapter. It's now ready to engage and challenge our learners. ",
    ],
    "statistics_controller" => [
        "reset_successfully" => "✅ Statistics reset successfully! 📊 All data has been reset, ensuring a fresh start for tracking progress and performance. ",
    ],
    "user_controller" => [
        "create" => "✅ Account successfully created! 🎉 The new account has been successfully created.",
        "update_profile" => "✅ Profile updated successfully! 🔄 Your profile information has been successfully updated. Thank you for keeping your details current! ",
        "block_switch" => "✅ Account block status updated successfully! 🚫 The block status of the account has been switched successfully. ",
        "delete_user" => "✅ Account and related data removed successfully! 🗑️ The account has been deleted along with all associated data. Cleanup complete! ",
        "reset_password" => "✅ We have reset the password for this account. Make sure to keep your password in a safe place"
    ],
    "user_watch_controller" => [
        "watch_registered" => "👀 Video watch registered! 📹 Your watch of the video has been successfully recorded by the system. Keep exploring our content! ",
    ],
    "video_controller" => [
        "link_not_correct" => "⚠️ Error: Invalid link! ⚠️ The link you provided is not correct or is broken. Please double-check the URL and try again. If you continue to experience issues, please contact support for assistance. Thank you! ",
    ]
];
